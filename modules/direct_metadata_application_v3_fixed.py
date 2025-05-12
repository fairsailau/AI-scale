#!/usr/bin/env python
"""
Handles the application of extracted metadata to files in Box.
Refactored to support applying metadata to single files
as independent tasks for concurrent processing.
"""

import streamlit as st
import logging
import json
import time # For UI refresh during background tasks (no longer used for polling threads)
import concurrent.futures # For concurrent processing
from boxsdk import Client, exception
from boxsdk.object.metadata import MetadataUpdate
from dateutil import parser
from datetime import timezone
from typing import Dict, Any, Tuple, List, Optional

# Assume utils is in .utils
from . import utils # Import utils module to use get_box_client

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Helper Functions ---

# IMPORTANT: This function should ONLY be called from the main Streamlit thread
# It uses st.session_state for caching.
if \'template_schema_cache\' not in st.session_state:
    st.session_state.template_schema_cache = {}

def get_template_schema(client: Client, full_scope: str, template_key: str) -> Optional[Dict[str, Any]]:
    """
    Fetches and caches template schema from Box.
    **IMPORTANT**: Call this only from the main Streamlit thread.
    """
    cache_key = f\'{full_scope}_{template_key}\'
    # Access st.session_state is SAFE here because this is assumed to be called
    # ONLY from the main Streamlit thread before background tasks start.
    if cache_key in st.session_state.template_schema_cache:
        logger.info(f"SF_APPLY: Using cached schema for {full_scope}/{template_key}")
        cached_schema = st.session_state.template_schema_cache[cache_key]
        # Return a copy to prevent modifications in thread (though threads won't call this)
        return cached_schema.copy() if isinstance(cached_schema, dict) else cached_schema
    try:
        logger.info(f"SF_APPLY: Fetching template schema for {full_scope}/{template_key}")
        template = client.metadata_template(full_scope, template_key).get()
        if template and hasattr(template, \'fields\') and template.fields:
            schema_map = {
                field[\'key\']: {\'type\': field[\'type\'], \'displayName\': field.get(\'displayName\', field[\'key\'])}
                for field in template.fields
            }
            # Writing to st.session_state is SAFE here (main thread)
            st.session_state.template_schema_cache[cache_key] = schema_map
            logger.info(f"SF_APPLY: Successfully fetched and cached schema for {full_scope}/{template_key}")
            return schema_map.copy()
        else:
            logger.warning(f"SF_APPLY: Template {full_scope}/{template_key} found but has no fields or is invalid.")
            # Writing to st.session_state is SAFE here (main thread)
            st.session_state.template_schema_cache[cache_key] = {} # Cache empty schema
            return {}
    except exception.BoxAPIException as e:
        logger.error(f"SF_APPLY: Box API Error fetching template schema for {full_scope}/{template_key}: Status={e.status}, Code={e.code}, Message={e.message}")
        # Writing to st.session_state is SAFE here (main thread)
        # Store specific error info in cache so the task function can give a specific message
        st.session_state.template_schema_cache[cache_key] = {"error_status": e.status, "error_code": e.code, "message": e.message}
        return None # Return None on error
    except Exception as e:
        logger.exception(f"SF_APPLY: Unexpected error fetching template schema for {full_scope}/{template_key}: {e}")
         # Writing to st.session_state is SAFE here (main thread)
        st.session_state.template_schema_cache[cache_key] = {"error_status": "general_error", "message": str(e)}
        return None # Return None on error

# Keep other helper functions like convert_value_for_template, flatten_metadata_for_template etc.
# as they were in your snippet, ensuring they do NOT access st.session_state or globals.
# They are assumed to be pure functions or use only passed arguments.

def convert_value_for_template(key: str, value: Any, field_type: str) -> Any:
    """Converts a value to the type specified by the Box metadata template field."""
    if value is None:
        return None
    original_value_repr = repr(value)
    try:
        if field_type == \'float\':
            if isinstance(value, str):
                cleaned_value = value.replace(\'$\', \'\').replace(\\,\', \'\').strip() # Added strip
                try: return float(cleaned_value)
                except ValueError: raise ConversionError(f"Could not convert string `{value}` to float for key `{key}`.")
            elif isinstance(value, (int, float)): return float(value)
            else: raise ConversionError(f"Value {original_value_repr} for key `{key}` is not a string or number.")
        elif field_type == \'date\':
            if isinstance(value, str):
                try:
                    # Handle common date formats, ensure timezone-aware UTC
                    dt = parser.parse(value)
                    dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                    return dt.strftime(\'%Y-%m-%dT%H:%M:%SZ\')
                except (parser.ParserError, ValueError) as e: raise ConversionError(f"Could not parse date string `{value}` for key `{key}`: {e}.")
            else: raise ConversionError(f"Value {original_value_repr} for key `{key}` is not a string.")
        elif field_type in [\'string\', \'enum\']:
            return str(value)
        elif field_type == \'multiSelect\':
            if isinstance(value, list): return [str(item) for item in value]
            elif isinstance(value, str):
                try:
                    # Attempt to parse a string list like '["item1", "item2"]'
                    if value.strip().startswith(\'[\') and value.strip().endswith(\"]\'):
                        parsed_list = json.loads(value)
                        if isinstance(parsed_list, list): return [str(item).strip() for item in parsed_list if str(item).strip()] # Ensure list of strings, skip empty
                except json.JSONDecodeError: pass # Not a JSON list string, treat as single item list below

                # If not a list or not a valid JSON list string, treat as single item list
                single_item = str(value).strip()
                return [single_item] if single_item else [] # Return list containing single item, or empty list if empty string
            else:
                 # Handle other types by converting to string and putting in a list
                 single_item = str(value).strip()
                 return [single_item] if single_item else []
        else:
            # For unknown types, attempt string conversion as a fallback, though this might fail Box validation later
            logger.warning(f"Attempting to convert value for unknown field type `{field_type}` for key `{key}`.")
            return str(value)

    except ConversionError: raise # Re-raise our custom error
    except Exception as e: raise ConversionError(f"Unexpected error converting value for key `{key}`: {e}")


def flatten_metadata_for_template(metadata_values: Dict[str, Any]) -> Dict[str, Any]:
    """Ensures metadata is a flat dictionary, handling common AI response structures."""
    if not isinstance(metadata_values, dict):
         logger.warning(f"flatten_metadata_for_template received non-dict input: {type(metadata_values)}")
         return {} # Return empty dict if input is not a dict

    flattened = {}

    # Prioritize direct keys unless 'answer' looks like a structured AI response
    is_structured_ai_response = isinstance(metadata_values.get('answer'), dict) and \
                                all(isinstance(v, dict) and 'value' in v for v in metadata_values.get('answer', {}).values())

    if is_structured_ai_response:
        logger.debug("Detected structured AI response format with 'answer'. Flattening.")
        for k, v_obj in metadata_values[\'answer\'].items():
            # Only include keys that correspond to actual fields we expect to map
            # (Further filtering will happen based on template schema)
            flattened[k] = v_obj[\'value\']
    else:
        logger.debug("AI response does not look like structured 'answer' format. Using top-level keys.")
        flattened = metadata_values.copy()

    # Remove common AI or wrapper keys from the final flattened dict
    keys_to_remove = [\'ai_agent_info\', \'created_at\', \'completion_reason\', \'answer\']
    for k_rem in keys_to_remove:
        flattened.pop(k_rem, None)

    return flattened


def filter_confidence_fields(metadata_values: Dict[str, Any]) -> Dict[str, Any]:
    """Removes _confidence fields."""
    if not isinstance(metadata_values, dict): return {}
    return {k: v for k, v in metadata_values.items() if not k.endswith(\'_confidence\')}

def parse_template_id(template_id_full: str) -> Tuple[str, str]:
    """Parses a full template ID (e.g., "enterprise_12345_templateKey") into scope and templateKey."""
    if not template_id_full or \'_\' not in template_id_full:
        raise ValueError(f"Invalid template ID format: {template_id_full}.")

    # Handle enterprise_<id>_<key> format
    if template_id_full.startswith("enterprise_"):
        parts = template_id_full.split(\'_\', 2) # Split at most twice
        if len(parts) == 3 and parts[1].isdigit():
             return f"{parts[0]}_{parts[1]}", parts[2] # scope = enterprise_id, key = templateKey
        # Fallback for simpler enterprise_key? Unlikely in practice for enterprise
        # return "enterprise", template_id_full.split(\'_\', 1)[1] if len(parts) > 1 else template_id_full

    # Handle other standard formats like global_key
    idx = template_id_full.rfind(\'_\')
    if idx == -1 or idx == 0 or idx == len(template_id_full) - 1:
         raise ValueError(f"Invalid template ID: {template_id_full}")

    scope = template_id_full[:idx]
    template_key = template_id_full[idx+1:]

    # Basic validation
    if not scope or not template_key:
         raise ValueError(f"Invalid template ID parts derived from {template_id_full}")

    return scope, template_key


# --- Single File Metadata Application Worker (MODIFIED) ---

MISSING_GLOBAL_PROPERTIES_ERROR_MSG = "The \'global/properties\' metadata template was not found. Please create it in Box Admin Console > Content > Metadata, or use the option on the View Results page to create a custom template from AI output."

def apply_metadata_to_single_file_task(
    box_config: Dict[str, Any], # NEW: Configuration for Box client
    file_id: str,
    file_name: str,
    raw_ai_response_values: Dict[str, Any],
    target_full_scope: str,
    target_template_key: str,
    template_schema: Optional[Dict[str, Any]] # NEW: Pass pre-fetched schema (or error info)
) -> Tuple[str, bool, str]: # Returns (file_id, success_boolean, message_string)
    """
    Applies metadata to a single file in a background thread.
    Accepts box_config and pre-fetched schema/schema error info.
    """
    template_identifier = f"{target_full_scope}/{target_template_key}"
    logger.info(f"TASK_APPLY: Starting for {file_name} (ID: {file_id}), template {template_identifier}")

    # Create Box client instance for this thread
    try:
        client = utils.get_box_client(box_config)
    except Exception as e:
        err = f"TASK_APPLY: Failed to create Box client for file {file_name} (ID: {file_id}): {e}"
        logger.error(err, exc_info=True)
        return file_id, False, err

    try:
        # Handle cases where schema pre-fetch failed in main thread
        if template_schema is None:
             # Check if error info was stored in the schema cache entry during pre-fetch
             # We can't access st.session_state here, but the calling code *might*
             # have passed a dict containing error info instead of None if schema fetch failed.
             # Let's assume the calling code passes None for simplicity if fetch failed.
             # So if template_schema is None, it means pre-fetching failed.
             # We can check if it was the specific global/properties case.
             if target_full_scope == "global" and target_template_key == "properties":
                 return file_id, False, MISSING_GLOBAL_PROPERTIES_ERROR_MSG
             else:
                  # If schema pre-fetch failed for another template
                 return file_id, False, f"Could not retrieve schema for {template_identifier} (pre-fetch failed or template not found)."

        # If schema object is a dict with error info (from pre-fetch failure)
        if isinstance(template_schema, dict) and template_schema.get("error_status"):
             err_status = template_schema.get("error_status")
             err_code = template_schema.get("error_code")
             err_msg_detail = template_schema.get("message", "Unknown pre-fetch error")
             if err_status == 404 and target_full_scope == "global" and target_template_key == "properties":
                  return file_id, False, MISSING_GLOBAL_PROPERTIES_ERROR_MSG
             else:
                  return file_id, False, f"Could not retrieve schema for {template_identifier} (Pre-fetch error: Status={err_status}, Code={err_code}, Msg={err_msg_detail})."


        if not template_schema:
             # Schema was fetched but was empty (template exists but has no fields)
             return file_id, True, f"Template schema for {template_identifier} is empty, nothing to apply."


        # Proceed with metadata application
        flat_metadata = flatten_metadata_for_template(raw_ai_response_values)
        metadata_no_conf = filter_confidence_fields(flat_metadata)

        final_md_ops = {}
        conv_errors = []
        for schema_k, field_detail in template_schema.items():
            field_type = field_detail.get(\'type\')
            if schema_k in metadata_no_conf:
                try:
                    conv_val = convert_value_for_template(schema_k, metadata_no_conf[schema_k], field_type)
                    # Only add if conversion was successful and value is not None/empty string (for strings/multiselect)
                    if conv_val is not None and not (isinstance(conv_val, str) and conv_val == "") and not (isinstance(conv_val, list) and not conv_val): # Check for empty string or empty list
                         final_md_ops[schema_k] = conv_val
                except ConversionError as e:
                    conv_errors.append(f"Key `{schema_k}`: {e}")
                except Exception as e: # Catch any other unexpected errors during conversion
                    conv_errors.append(f"Key `{schema_k}`: Unexpected conversion error - {e}")


        if not final_md_ops:
            base_msg = f"No mappable or valid metadata found to apply for {file_name} to template {template_identifier}."
            if conv_errors: return file_id, False, f"{base_msg} Conversion errors: {'; '.join(conv_errors)}"
            return file_id, True, base_msg # Success if no metadata to apply (might be intentional)

        # Use the client created in THIS thread
        md_instance = client.file(file_id).metadata(scope=target_full_scope, template=target_template_key)
        try:
            # Attempt to update existing metadata instance
            update_ops = []
            for k_up, v_up in final_md_ops.items():
                # Box SDK update requires [test] for multi-select, not ["test"]
                update_ops.append({"op": "replace", "path": f"/{k_up}", "value": v_up})

            if update_ops:
                 # Using client.file(...).metadata(...).update(update_ops) is another way
                 # Need to check which method is preferred/more reliable
                 # Using the object method from your snippet:
                 update_obj = MetadataUpdate()
                 for k_up, v_up in final_md_ops.items(): update_obj.add_update(MetadataUpdate.OP_REPLACE, f"/{k_up}", v_up)

                 if update_obj.get_updates_list():
                      md_instance.update(update_obj)
                      logger.info(f"TASK_APPLY: Successfully updated metadata for {file_name}")
                      msg = f"Metadata successfully updated on {template_identifier}. {len(final_md_ops)} fields."
                 else:
                      msg = "No valid fields to update." # Should not happen if final_md_ops is not empty and update_ops was built
            else:
                 msg = "No update operations generated." # Should match "No mappable or valid metadata" above

        except exception.BoxAPIException as e_box:
            if e_box.status == 404: # Metadata instance not found, create new
                md_instance.create(final_md_ops)
                logger.info(f"TASK_APPLY: Successfully created metadata for {file_name}")
                msg = f"Metadata successfully created on {template_identifier}. {len(final_md_ops)} fields."
            else:
                 # Re-raise the Box API exception if it's not a 404
                 raise

        if conv_errors:
            # Append conversion errors to the message
            return file_id, True, f"{msg} Conversion errors occurred for some fields: {'; '.join(conv_errors)}"

        return file_id, True, msg

    except exception.BoxAPIException as e_box_outer:
        err = f"Box API Error for {file_name} (ID {file_id}) on {template_identifier}: Status={e_box_outer.status}, Code={e_box_outer.code}, Message={e_box_outer.message}"
        # Add more detailed error info if available
        if e_box_outer.context_info and 'errors' in e_box_outer.context_info and isinstance(e_box_outer.context_info['errors'], list):
             for err_detail in e_box_outer.context_info['errors']:
                  detail_msg = err_detail.get('message') or err_detail.get('reason')
                  if detail_msg: err += f" - {detail_msg}"
                  if err_detail.get('name') and err_detail.get('value'): err += f" (Field: {err_detail['name']} Value: {err_detail['value']})"

        logger.error(f"TASK_APPLY: {err}", exc_info=True)
        return file_id, False, err
    except Exception as e_outer:
        err = f"Unexpected error for {file_name} (ID {file_id}) on {template_identifier}: {str(e_outer)}"
        logger.error(f"TASK_APPLY: {err}", exc_info=True)
        return file_id, False, err

# --- Orchestration for background tasks (MODIFIED - collects results locally) ---
def run_application_tasks_background(
    files_to_apply: List[Dict[str,Any]],
    max_workers: int,
    box_config: Dict[str, Any], # Pass Box config
    template_schemas_map: Dict[str, Dict[str, Any]] # Pass pre-fetched schemas (or error info dicts)
) -> Dict[str, Tuple[bool, str]]: # Returns {file_id: (success, message)}
    """
    Orchestrates metadata application for multiple files using ThreadPoolExecutor.
    Collects results and returns them. This function blocks until all tasks complete.
    Each item in files_to_apply should be a dict:
    {\'file_id\': str, \'file_name\': str, \'ai_response\': dict, \'template_id_for_application\': str}
    """
    logger.info(f"Starting concurrent metadata application for {len(files_to_apply)} files with {max_workers} workers...")

    application_results_collected = {} # Use a local dict to collect results

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file_id = {}
        tasks_submitted_count = 0 # Track how many tasks were actually submitted

        for task_data in files_to_apply:
            file_id = task_data[\'file_id\']
            file_name = task_data.get(\'file_name\', f\'File {file_id}\')
            ai_response = task_data[\'ai_response\']
            template_id_for_app = task_data.get(\'template_id_for_application\') # Can be None or "freeform_prompt_based"

            target_full_scope = "global"
            target_template_key = "properties" # Default for freeform/unspecified
            template_schema_for_task = None # This will hold the schema dict or error dict/None

            # Determine the target template and get the pre-fetched schema/error info
            if template_id_for_app and template_id_for_app != "freeform_prompt_based":
                try:
                    target_full_scope, target_template_key = parse_template_id(template_id_for_app)
                    schema_map_key = f\'{target_full_scope}_{target_template_key}\'
                    template_schema_for_task = template_schemas_map.get(schema_map_key)
                    # Note: template_schema_for_task can be a dict (the schema), {} (empty schema), or None (pre-fetch failed/404) or {error_status: ...}

                    if template_schema_for_task is None or (isinstance(template_schema_for_task, dict) and template_schema_for_task.get("error_status") == 404):
                         # If pre-fetch resulted in None or a 404 error dict, make the task fail with a specific message
                         error_msg = f"Metadata template {template_id_for_app} not found or pre-fetch failed."
                         logger.warning(f"Skipping task for {file_name} due to missing/failed pre-fetch of template {template_id_for_app}.")
                         application_results_collected[file_id] = (False, error_msg)
                         continue # Skip submitting this task

                except ValueError as e_parse:
                    err_msg = f"Invalid template ID format {template_id_for_app}: {e_parse}. Skipping task submission for {file_name}."
                    logger.error(err_msg)
                    application_results_collected[file_id] = (False, err_msg)
                    continue # Skip submitting this task

            elif template_id_for_app == "freeform_prompt_based" or not template_id_for_app:
                 # Freeform defaults to global/properties. Check if schema is pre-fetched.
                 schema_map_key = "global_properties"
                 template_schema_for_task = template_schemas_map.get(schema_map_key)
                 # Note: template_schema_for_task can be the schema dict, {} (empty), None, or {error_status: ...}

                 if template_schema_for_task is None or (isinstance(template_schema_for_task, dict) and template_schema_for_task.get("error_status") == 404):
                     # If pre-fetch resulted in None or a 404 error dict for global/properties, make the task fail specifically
                     logger.warning(f"Skipping task for {file_name} due to missing/failed pre-fetch of template global/properties (freeform default).")
                     application_results_collected[file_id] = (False, MISSING_GLOBAL_PROPERTIES_ERROR_MSG) # Use the standard message
                     continue # Skip submitting this task


            # If we reached here, the template schema/error info was found in the pre-fetched map
            # and was not a 404 or None, so submit the task.
            future = executor.submit(
                apply_metadata_to_single_file_task,
                box_config, # Pass config
                file_id,
                file_name,
                ai_response,
                target_full_scope,
                target_template_key,
                template_schema_for_task # Pass pre-fetched schema or non-404 error info dict
            )
            future_to_file_id[future] = file_id
            tasks_submitted_count += 1

        # This loop BLOCKS the calling thread (main Streamlit thread) until all futures are done
        # Only iterate over futures that were actually submitted
        for future in concurrent.futures.as_completed(future_to_file_id):
            completed_file_id = future_to_file_id[future]
            try:
                f_id, success, message = future.result()
                 # Collect results in the local dictionary
                application_results_collected[f_id] = (success, message)
                # logger.info(f"TASK_APPLY_RUNNER: Finished file ID {f_id}. Success: {success}. Message: {message}") # Verbose
            except Exception as exc:
                logger.error(f"TASK_APPLY_RUNNER: File ID {completed_file_id} generated an exception: {exc}", exc_info=True)
                 # Collect error in the local dictionary
                application_results_collected[completed_file_id] = (False, str(exc))

    logger.info("Concurrent metadata application job finished.")
    return application_results_collected # Return the collected results
