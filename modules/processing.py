#!/usr/bin/env python
"""
Streamlit page for processing files via Box AI for metadata extraction.
Includes orchestration of background tasks using concurrent.futures (blocking UI).
"""
import streamlit as st
import time
import logging
from typing import List, Dict, Any, Optional, Tuple
import json
import concurrent.futures # Used for ThreadPoolExecutor
# Assume utils, processing, metadata_application are in modules/
from modules import utils
from modules import processing # Assuming processing logic is here
from modules import metadata_application # Assuming metadata application logic is here (for get_template_schema etc.)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Single file processing function (Moved to modules/processing.py) ---
# This function is now defined in modules/processing.py and imported.


# --- Orchestration for background tasks (Moved to modules/processing.py) ---
# This function is now defined in modules/processing.py and imported.


# Need the get_template_id_for_file_processing helper function here
# It was in your original processing.py snippet. Let's keep it here
# if it's primarily used by the UI page logic to determine templates.
# If it's also used by the worker, it needs to be importable by the worker too.
# For now, assuming it's only used in the main thread for pre-fetching fields.
def get_template_id_for_file_processing(
    file_id: str,
    file_doc_type: Optional[str],
    metadata_config: Dict[str, Any],
    document_type_to_template_mapping: Dict[str, str]
) -> Optional[str]:
    """
    Determines the template ID for a file based on config and categorization for processing.
    NOTE: This helper is used by the main thread pre-fetching logic.
    """
    extraction_method = metadata_config.get('extraction_method', 'freeform')
    if extraction_method == 'structured':
        # Prioritize specific doc type mapping if available
        if file_doc_type and document_type_to_template_mapping:
            mapped_template_id = document_type_to_template_mapping.get(file_doc_type)
            if mapped_template_id:
                # logger.info(f'File ID {file_id} (type {file_doc_type}): Using mapped template {mapped_template_id} for processing.') # Verbose
                return mapped_template_id
        # Fallback to global structured template
        global_structured_template_id = metadata_config.get('template_id')
        if global_structured_template_id:
            # logger.info(f'File ID {file_id}: No specific mapping for type {file_doc_type}. Using global structured template {global_structured_template_id} for processing.') # Verbose
            return global_structured_template_id
        logger.warning(f'File ID {file_id}: No template ID found for structured extraction (no mapping for type {file_doc_type} and no global template).')
        return None
    elif extraction_method == \'freeform\':
        # Freeform doesn\'t strictly need a template ID for the AI *call*,
        # but the concept exists for where the *result* might eventually go.
        # The worker task uses "freeform_prompt_based" as an internal identifier.
        # This function is for getting a template ID *before* the task for pre-fetching fields.
        # For freeform, we don\'t pre-fetch fields, so this function isn't strictly
        # needed for the freeform case in the pre-fetching logic, but keep it for completeness.
        logger.debug(f"File ID {file_id}: Freeform extraction. No specific template ID used for pre-fetching fields.")
        return None # Return None as no template fields are needed for freeform AI call
    return None # Should not be reached


# --- Main Streamlit Page Function (Refactored for Blocking Background Tasks) ---
def process_files():
    """
    Main Streamlit page function for processing files.
    Handles UI, configuration, and orchestrates background extraction (blocking).
    """
    st.title(\'Process Files for AI Metadata Extraction\')

    # Initialize session state variables (Keep these)
    if \'extraction_results\' not in st.session_state: st.session_state.extraction_results = {}
    # Document categorization is needed by the task, ensure its structure exists
    if \'document_categorization\' not in st.session_state:
         st.session_state.document_categorization = {\'results\': {}, \'config\': {}, \'job_status\': {\'is_running\': False}} # Ensure job_status is initialized

    # New state variables for blocking job status
    if \'extraction_job_running\' not in st.session_state: st.session_state.extraction_job_running = False
    if \'extraction_job_summary\' not in st.session_state: st.session_state.extraction_job_summary = None


    try:
        # Basic checks (Keep these)
        if not st.session_state.get(\'authenticated\') or not st.session_state.get(\'client\'):
            st.error(\'Please authenticate with Box first.\')
            if st.button(\'Go to Login\'): st.session_state.current_page = \'Home\'; st.rerun()
            return

        if not st.session_state.get(\'selected_files\'):
            st.warning(\'No files selected. Please select files in the File Browser first.\')
            if st.button(\'Go to File Browser\'): st.session_state.current_page = \'File Browser\'; st.rerun()
            return

        metadata_config_state = st.session_state.get(\'metadata_config\')
        # Need categorization results for getting doc type for mapping
        categorization_results = st.session_state.get(\'document_categorization\', {}).get(\'results\', {})
        doc_type_mapping = st.session_state.get(\'document_type_to_template\', {})

        # Check if structured extraction is selected and if necessary configs are missing
        is_structured = metadata_config_state.get(\'extraction_method\') == \'structured\'
        global_structured_template_id = metadata_config_state.get(\'template_id\')
        has_any_mapping = any(doc_type_mapping.values()) # Check if the mapping dict has any non-empty values

        is_structured_incomplete = is_structured and not global_structured_template_id and not has_any_mapping

        if not metadata_config_state or is_structured_incomplete:
            warning_msg = \'Metadata configuration is incomplete.\'
            if is_structured:
                 warning_msg += \' For structured extraction, please ensure a global template is selected or document types are mapped to templates.\'
            st.warning(warning_msg)
            if st.button(\'Go to Metadata Configuration\'): st.session_state.current_page = \'Metadata Configuration\'; st.rerun()
            return
        # End Basic Checks

        st.write(f"Ready to process {len(st.session_state.selected_files)} files.")

        # Get Box Config for worker threads *before* starting
        box_config_for_worker = utils.get_box_config_for_worker(st.session_state)
        if not box_config_for_worker:
             st.error("Could not retrieve Box configuration for background tasks. Please check credentials and config.")
             # Maybe add a button to go to config/login?
             return # Cannot proceed without config


        # Pre-fetch template schema fields needed for Structured Extraction *in the main thread*
        structured_template_fields_map = {}
        if is_structured:
             st.info("Pre-fetching template schemas for structured extraction...")
             main_client = st.session_state.client # Use the main client here

             # Identify all template IDs that might be used
             templates_to_fetch = set()

             # Add global template if specified and looks like an ID (scope_key)
             if global_structured_template_id and \
                metadata_application.parse_template_id(global_structured_template_id): # Use parser to validate format
                 templates_to_fetch.add(global_structured_template_id)
                 logger.debug(f"Added global template {global_structured_template_id} for pre-fetch.")
             elif global_structured_template_id:
                  st.warning(f"Global template ID format invalid: {global_structured_template_id}. Skipping pre-fetch.")
                  logger.error(f"Invalid global template ID format: {global_structured_template_id}")


             # Add templates from doc type mapping that match selected files
             files_list = list(st.session_state.selected_files)
             for file_data in files_list:
                 file_id = str(file_data[\'id\'])
                 file_doc_type = categorization_results.get(file_id, {}).get(\'document_type\')
                 mapped_tpl_id = get_template_id_for_file_processing(
                      file_id, file_doc_type, metadata_config_state, doc_type_mapping
                 )
                 if mapped_tpl_id and mapped_tpl_id != global_structured_template_id:
                      # Only add mapped template if it\'s not the same as the global one
                      templates_to_fetch.add(mapped_tpl_id)
                      logger.debug(f"Added mapped template {mapped_tpl_id} for file {file_id} pre-fetch.")


             if not templates_to_fetch:
                  st.warning("No valid template IDs determined for pre-fetching structured fields.")
                  logger.warning("No templates identified for structured extraction pre-fetching.")

             # Fetch schema for identified templates
             for tpl_id in templates_to_fetch:
                 try:
                     scope, key = metadata_application.parse_template_id(tpl_id)
                     # Use the get_template_schema from metadata_application (it uses st.session_state cache safely)
                     schema = metadata_application.get_template_schema(main_client, scope, key)
                     # schema can be a dict (schema), {} (empty schema), or {error_status: ...} (error) or None (error)

                     if schema and not (isinstance(schema, dict) and schema.get(\'error_status\')):
                         # If schema was successfully fetched and is not an error dict
                         # Convert schema to the fields format expected by the task function
                         fields_for_ai = []
                         for field_key, field_info in schema.items():
                             field_type_val = field_info.get(\'type\', \'string\') if isinstance(field_info, dict) else \'string\' # Handle potential non-dict info
                             display_name_val = field_info.get(\'displayName\', field_key.replace(\'_\', \' \').title()) if isinstance(field_info, dict) else field_key.replace(\'_\', \' \').title()
                             fields_for_ai.append({\'key\': field_key, \'type\': field_type_val, \'displayName\': display_name_val})
                         structured_template_fields_map[tpl_id] = fields_for_ai
                         logger.info(f"Successfully pre-fetched and formatted fields for {tpl_id}.")
                     elif isinstance(schema, dict) and schema.get(\'error_status\'):
                          st.warning(f"Could not pre-fetch schema for template ID {tpl_id}. Box API Error: {schema.get(\'message\', \'Unknown\')}. Check console.")
                          logger.error(f"Failed to pre-fetch schema for {tpl_id} with error info: {schema}")
                          # Optionally store the error info in the map so the worker task knows why it failed
                          structured_template_fields_map[tpl_id] = schema # Store error dict
                     else: # schema is None
                          st.warning(f"Could not pre-fetch schema for template ID {tpl_id}. Unknown error during fetch. Check console.")
                          logger.error(f"Failed to pre-fetch schema for {tpl_id} (result was None).")
                          # Optionally store None or a generic error indicator
                          structured_template_fields_map[tpl_id] = {"error_status": "fetch_failed", "message": "Unknown error during schema fetch."} # Store error dict

                 except ValueError as e:
                     st.warning(f"Invalid template ID format encountered during pre-fetch ({tpl_id}): {e}. Skipping.")
                     logger.error(f"Invalid template ID format during pre-fetch: {tpl_id}: {e}")
                 except Exception as e:
                     st.error(f"Unexpected error during schema pre-fetch for {tpl_id}: {e}")
                     logger.error(f"Unexpected error pre-fetching schema for {tpl_id}: {e}", exc_info=True)
                     structured_template_fields_map[tpl_id] = {"error_status": "unexpected_error", "message": f"Unexpected error: {e}"} # Store error dict

             if is_structured and not structured_template_fields_map and has_any_mapping or (global_structured_template_id and not structured_template_fields_map):
                 st.error("Structured extraction is configured, but no template schemas could be pre-fetched successfully. Please check template IDs and permissions.")
                 # Consider disabling the start button or returning here if pre-fetch is critical
                 # For now, let the task fail gracefully if fields are missing


        # Start Button Logic (Modified)
        start_button = st.button(
            \'Start Parallel Extraction Job\',
            disabled=st.session_state.extraction_job_running, # Use the new flag
            use_container_width=True,
            key=\'start_bg_extraction_button\'
        )

        # Display progress/status if job is running or finished
        if st.session_state.extraction_job_running:
            st.info("Extraction job is running. The UI will update when it completes (this might take a while for many files).")
            # Use st.progress if you can estimate total steps, but for blocking call, a spinner is better
            # st.progress(st.session_state.extraction_job_summary.get('processed_count', 0) / st.session_state.extraction_job_summary.get('total_files', 1)) # Would need a polling mechanism
            with st.spinner('Processing files... Please wait.'):
                 # The blocking call happens below, after the button logic
                 pass # Spinner will show while the function runs

        # This block executes in the rerun where extraction_job_running is True
        if start_button and not st.session_state.extraction_job_running:
             st.session_state.extraction_job_running = True
             st.session_state.extraction_job_summary = None # Clear previous summary
             st.session_state.extraction_results = {} # Clear previous results
             # Ensure categorization results are stored for the worker to access via the passed dict
             # st.session_state.document_categorization is already the dict passed to the worker orchestrator

             # Trigger a rerun immediately to show the "Running..." state and spinner
             st.rerun()

        # This code will execute in the rerun where extraction_job_running is True and summary is None
        if st.session_state.extraction_job_running and not st.session_state.extraction_job_summary:
            # *** THIS CALL WILL BLOCK THE STREAMLIT UI ***
            logger.info(\'Calling blocking run_extraction_tasks_background...\')
            files_list_for_processing = list(st.session_state.selected_files) # Ensure it\'s a list
            categorization_for_tasks = st.session_state.get(\'document_categorization\', {}) # Pass the whole dict

            # Catch errors during the blocking call
            try:
                collected_results = processing.run_extraction_tasks_background(
                    files_list_for_processing,
                    max_workers_bg,
                    box_config_for_worker, # Pass config
                    metadata_config_state, # Pass config
                    categorization_for_tasks, # Pass categorization
                    doc_type_mapping, # Pass mapping
                    structured_template_fields_map # Pass pre-fetched fields map
                )

                # --- Update session state AFTER the blocking call returns ---
                success_count = 0
                error_count = 0
                final_extraction_results = {} # This is where the actual results {file_id: {ai_response: ..., template_id: ...}} go
                file_status_details = {} # This is for the summary display {file_id: {name, status, message}}

                # Get original file names for summary details
                original_selected_files = st.session_state.get(\'selected_files\', [])
                original_file_names = {str(f[\'id\']): f.get(\'name\', str(f[\'id\'])) for f in original_selected_files}


                for file_id, (success, result_or_error) in collected_results.items():
                    file_name_detail = original_file_names.get(file_id, file_id) # Get name if available

                    if success:
                        success_count += 1
                        final_extraction_results[file_id] = result_or_error # Store the result payload
                        file_status_details[file_id] = {"file_name": file_name_detail, "status": "Success", "message": "Extraction successful."}
                    else:
                        error_count += 1
                        file_status_details[file_id] = {"file_name": file_name_detail, "status": "Error", "message": str(result_or_error)}
                        # Optionally store the error message in extraction_results if the View Results page needs it
                        final_extraction_results[file_id] = {"error": str(result_or_error)}


                st.session_state.extraction_results = final_extraction_results
                st.session_state.extraction_job_summary = {
                    \'total_files\': len(files_list_for_processing),
                    \'success_count\': success_count,
                    \'error_count\': error_count,
                    \'details\': file_status_details
                }
                st.session_state.extraction_job_running = False # Mark job as finished
                logger.info("Blocking extraction call returned. Session state updated.")

            except Exception as e:
                logger.error(f"Error during blocking extraction task execution: {e}", exc_info=True)
                # Create a summary indicating all files failed due to the job error
                files_list_for_processing = st.session_state.get(\'selected_files\', []) # Re-get files if needed
                original_file_names = {str(f[\'id\']): f.get(\'name\', str(f[\'id\'])) for f in files_list_for_processing}

                st.session_state.extraction_job_summary = {
                     \'total_files\': len(files_list_for_processing),
                     \'success_count\': 0,
                     \'error_count\': len(files_list_for_processing),
                     \'details\': {str(f[\'id\']): {"file_name": original_file_names.get(str(f[\'id\']), str(f[\'id\'])), "status": "Failed", "message": f"Job failed due to unexpected error: {e}"} for f in files_list_for_processing}
                }
                st.session_state.extraction_results = {} # Clear results on job failure
                st.session_state.extraction_job_running = False # Mark job as finished
                st.error(f"An unexpected error occurred during processing: {e}")


            # Rerun to display the final status and results
            st.rerun()


        # Display final job summary AFTER the job is complete (extraction_job_running is False)
        if not st.session_state.extraction_job_running and st.session_state.extraction_job_summary:
            summary = st.session_state.extraction_job_summary
            st.subheader("Extraction Job Summary")
            st.write(f"Total files: {summary[\'total_files\']}")
            st.write(f"Successfully extracted: {summary[\'success_count\']}")
            st.write(f"Errors: {summary[\'error_count\']}")

            if summary[\'error_count\'] > 0:
                 st.warning("Some files failed extraction. Check detailed status below.")

            with st.expander("Detailed Results Summary", expanded=False):
                 if summary.get(\'details\'):
                     for file_id, detail in summary[\'details\'].items():
                         icon = "✅" if detail[\'status\'] == \'Success\' else "❌"
                         st.markdown(f"**{detail[\'file_name\']} ({file_id})**: {icon} {detail[\'status\"]}")
                         if detail[\'message\'] and detail[\'status\'] != \'Success\':
                             st.error(f"> {detail[\'message\"]}")
                         elif detail[\'message\'] and detail[\'status\'] == \'Success\':
                             st.info(f"> {detail[\'message\"]}") # Show success messages too

            # Add navigation to results page
            # Only show button if there are successful results to view
            if st.session_state.extraction_results: # Check if extraction_results is not empty
                 if st.button("View Successful Extraction Results", key=\'go_to_results_after_extraction\'):
                     # Set selected_result_ids to successful ones if the View Results page needs it
                     successful_ids = [f_id for f_id, (success, _) in collected_results.items() if success] # Use local results
                     st.session_state.selected_result_ids = successful_ids
                     st.session_state.current_page = "View Results"
                     st.rerun()


    except Exception as e:
        logger.error(f"An error occurred in the process_files page (top level): {e}", exc_info=True)
        st.error(f"An unexpected error occurred in the application: {e}")

# Ensure this page function is called when the user navigates to this page
# This depends on your main app.py or navigation logic.
# Example:
# if st.session_state.current_page == "Process Files":
#     process_files()
