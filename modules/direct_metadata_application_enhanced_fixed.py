import streamlit as st
import logging
import json
from boxsdk import Client

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_metadata_format(metadata_values):
    """
    Fix the metadata format by converting string representations of dictionaries
    to actual Python dictionaries.
    
    Args:
        metadata_values (dict): The original metadata values dictionary
        
    Returns:
        dict: A new dictionary with properly formatted metadata values
    """
    formatted_metadata = {}
    
    for key, value in metadata_values.items():
        # If the value is a string that looks like a dictionary, parse it
        if isinstance(value, str) and value.startswith('{') and value.endswith('}'):
            try:
                # Replace single quotes with double quotes for JSON compatibility
                json_compatible_str = value.replace("'", '"')
                # Parse the string representation into a proper Python dictionary
                parsed_value = json.loads(json_compatible_str)
                formatted_metadata[key] = parsed_value
            except json.JSONDecodeError:
                # If parsing fails, keep the original string value
                formatted_metadata[key] = value
        else:
            # For non-dictionary string values, keep as is
            formatted_metadata[key] = value
    
    return formatted_metadata

def flatten_metadata_for_template(metadata_values):
    """
    Flatten the metadata structure by extracting fields from the 'answer' object
    and placing them directly at the top level to match the template structure.
    
    Args:
        metadata_values (dict): The metadata values with nested objects
        
    Returns:
        dict: A flattened dictionary with fields at the top level
    """
    flattened_metadata = {}
    
    # Check if 'answer' exists and is a dictionary
    if 'answer' in metadata_values and isinstance(metadata_values['answer'], dict):
        # Extract fields from the 'answer' object and place them at the top level
        for key, value in metadata_values['answer'].items():
            flattened_metadata[key] = value
    else:
        # If there's no 'answer' object, use the original metadata
        flattened_metadata = metadata_values.copy()
    
    # Remove any non-template fields that shouldn't be sent to Box API
    # These are fields that are used internally but not part of the template
    keys_to_remove = ['ai_agent_info', 'created_at', 'completion_reason', 'answer']
    for key in keys_to_remove:
        if key in flattened_metadata:
            del flattened_metadata[key]
    
    return flattened_metadata

def apply_metadata_direct():
    """
    Direct approach to apply metadata to Box files with comprehensive fixes
    for session state alignment and metadata extraction
    """
    st.title("Apply Metadata")
    
    # Debug checkbox
    debug_mode = st.sidebar.checkbox("Debug Session State", key="debug_checkbox")
    if debug_mode:
        st.sidebar.write("### Session State Debug")
        st.sidebar.write("**Session State Keys:**")
        st.sidebar.write(list(st.session_state.keys()))
        
        if "client" in st.session_state:
            st.sidebar.write("**Client:** Available")
            try:
                user = st.session_state.client.user().get()
                st.sidebar.write(f"**Authenticated as:** {user.name}")
            except Exception as e:
                st.sidebar.write(f"**Client Error:** {str(e)}")
        else:
            st.sidebar.write("**Client:** Not available")
            
        if "processing_state" in st.session_state:
            st.sidebar.write("**Processing State Keys:**")
            st.sidebar.write(list(st.session_state.processing_state.keys()))
            
            # Dump the first processing result for debugging
            if st.session_state.processing_state:
                first_key = next(iter(st.session_state.processing_state))
                st.sidebar.write(f"**First Processing Result ({first_key}):**")
                st.sidebar.json(st.session_state.processing_state[first_key])
    
    # Check if client exists directly
    if 'client' not in st.session_state:
        st.error("Box client not found. Please authenticate first.")
        if st.button("Go to Authentication", key="go_to_auth_btn"):
            st.session_state.current_page = "Home"  # Assuming Home page has authentication
            st.rerun()
        return
    
    # Get client directly
    client = st.session_state.client
    
    # Verify client is working
    try:
        user = client.user().get()
        logger.info(f"Verified client authentication as {user.name}")
        st.success(f"Authenticated as {user.name}")
    except Exception as e:
        logger.error(f"Error verifying client: {str(e)}")
        st.error(f"Authentication error: {str(e)}. Please re-authenticate.")
        if st.button("Go to Authentication", key="go_to_auth_error_btn"):
            st.session_state.current_page = "Home"
            st.rerun()
        return
    
    # Check if processing state exists
    if "processing_state" not in st.session_state or not st.session_state.processing_state:
        st.warning("No processing results available. Please process files first.")
        if st.button("Go to Process Files", key="go_to_process_files_btn"):
            st.session_state.current_page = "Process Files"
            st.rerun()
        return
    
    # Debug the structure of processing_state
    processing_state = st.session_state.processing_state
    logger.info(f"Processing state keys: {list(processing_state.keys())}")
    
    # Add debug dump to sidebar
    st.sidebar.write("🔍 RAW processing_state")
    st.sidebar.json(processing_state)
    
    # Extract file IDs and metadata from processing_state
    available_file_ids = []
    
    # Check if we have any selected files in session state
    if "selected_files" in st.session_state and st.session_state.selected_files:
        selected_files = st.session_state.selected_files
        logger.info(f"Found {len(selected_files)} selected files in session state")
        for file_info in selected_files:
            if isinstance(file_info, dict) and "id" in file_info and file_info["id"]:
                # CRITICAL FIX: Ensure file ID is a string
                file_id = str(file_info["id"])
                file_name = file_info.get("name", "Unknown")
                available_file_ids.append(file_id)
                logger.info(f"Added file ID {file_id} from selected_files")
    
    # Pull out the real per‐file results dict
    results_map = processing_state.get("results", {})
    logger.info(f"Results map keys: {list(results_map.keys())}")
    
    file_id_to_metadata = {}
    file_id_to_file_name = {}
    
    # Initialize file_id_to_file_name from selected_files
    if "selected_files" in st.session_state and st.session_state.selected_files:
        for i, file_info in enumerate(st.session_state.selected_files):
            if isinstance(file_info, dict) and "id" in file_info and file_info["id"]:
                file_id = str(file_info["id"])
                file_id_to_file_name[file_id] = file_info.get("name", f"File {file_id}")
    
    for raw_id, payload in results_map.items():
        file_id = str(raw_id)
        available_file_ids.append(file_id)
        
        # Most APIs put your AI fields under payload["results"]
        metadata = payload.get("results", payload)
        
        # If metadata is a string that looks like JSON, try to parse it
        if isinstance(metadata, str):
            try:
                parsed_metadata = json.loads(metadata)
                if isinstance(parsed_metadata, dict):
                    metadata = parsed_metadata
            except json.JSONDecodeError:
                # Not valid JSON, keep as is
                pass
        
        # If payload has an "answer" field that's a JSON string, parse it
        if isinstance(payload, dict) and "answer" in payload and isinstance(payload["answer"], str):
            try:
                parsed_answer = json.loads(payload["answer"])
                if isinstance(parsed_answer, dict):
                    metadata = parsed_answer
            except json.JSONDecodeError:
                # Not valid JSON, keep as is
                pass
        
        file_id_to_metadata[file_id] = metadata
        logger.info(f"Extracted metadata for {file_id}: {metadata!r}")
    
    # Remove duplicates while preserving order
    available_file_ids = list(dict.fromkeys(available_file_ids))
    
    # Debug logging
    logger.info(f"Available file IDs: {available_file_ids}")
    logger.info(f"File ID to file name mapping: {file_id_to_file_name}")
    logger.info(f"File ID to metadata mapping: {list(file_id_to_metadata.keys())}")
    
    st.write("Apply extracted metadata to your Box files.")
    
    # Display selected files
    st.subheader("Selected Files")
    
    if not available_file_ids:
        st.error("No file IDs available for metadata application. Please process files first.")
        if st.button("Go to Process Files", key="go_to_process_files_error_btn"):
            st.session_state.current_page = "Process Files"
            st.rerun()
        return
    
    st.write(f"You have selected {len(available_file_ids)} files for metadata application.")
    
    with st.expander("View Selected Files"):
        for file_id in available_file_ids:
            file_name = file_id_to_file_name.get(file_id, "Unknown")
            st.write(f"- {file_name} ({file_id})")
    
    # Metadata application options
    st.subheader("Application Options")
    
    # For freeform extraction
    st.write("Freeform extraction results will be applied as properties metadata.")
    
    # Option to normalize keys
    normalize_keys = st.checkbox(
        "Normalize keys",
        value=True,
        help="If checked, keys will be normalized (lowercase, spaces replaced with underscores).",
        key="normalize_keys_checkbox"
    )
    
    # Option to filter placeholder values
    filter_placeholders = st.checkbox(
        "Filter placeholder values",
        value=True,
        help="If checked, placeholder values like 'insert date' will be filtered out.",
        key="filter_placeholders_checkbox"
    )
    
    # Batch size (simplified to just 1)
    st.subheader("Batch Processing Options")
    st.write("Using single file processing for reliability.")
    
    # Operation timeout
    timeout_seconds = st.slider(
        "Operation Timeout (seconds)",
        min_value=10,
        max_value=300,
        value=60,
        help="Maximum time to wait for each operation to complete.",
        key="timeout_slider"
    )
    
    # Apply metadata button
    col1, col2 = st.columns(2)
    
    with col1:
        apply_button = st.button(
            "Apply Metadata",
            use_container_width=True,
            key="apply_metadata_btn"
        )
    
    with col2:
        cancel_button = st.button(
            "Cancel",
            use_container_width=True,
            key="cancel_btn"
        )
    
    # Progress tracking
    progress_container = st.container()
    
    # Function to check if a value is a placeholder
    def is_placeholder(value):
        """Check if a value appears to be a placeholder"""
        if not isinstance(value, str):
            return False
            
        placeholder_indicators = [
            "insert", "placeholder", "<", ">", "[", "]", 
            "enter", "fill in", "your", "example"
        ]
        
        value_lower = value.lower()
        return any(indicator in value_lower for indicator in placeholder_indicators)
    
    # Direct function to apply metadata to a single file
    def apply_metadata_to_file_direct(client, file_id, metadata_values, doc_type): # Added doc_type
        """
        Apply metadata to a single file with direct client reference
        
        Args:
            client: Box client object
            file_id: File ID to apply metadata to
            metadata_values: Dictionary of metadata values to apply
            
        Returns:
            dict: Result of metadata application
        """
        try:
            file_name = file_id_to_file_name.get(file_id, "Unknown")
            
            # CRITICAL FIX: Validate metadata values
            if not metadata_values:
                logger.error(f"No metadata found for file {file_name} ({file_id})")
                return {
                    "file_id": file_id,
                    "file_name": file_name,
                    "success": False,
                    "error": "No metadata found for this file"
                }
            
            # Log original metadata values for debugging
            logger.info(f"Original metadata values for file {file_name} ({file_id}): {json.dumps(metadata_values, default=str)}")
            
            # Filter out placeholder values if requested
            if filter_placeholders:
                filtered_metadata = {}
                for key, value in metadata_values.items():
                    if not is_placeholder(value):
                        filtered_metadata[key] = value
                
                # If all values were placeholders, keep at least one for debugging
                if not filtered_metadata and metadata_values:
                    # Get the first key-value pair
                    first_key = next(iter(metadata_values))
                    filtered_metadata[first_key] = metadata_values[first_key]
                    filtered_metadata["_note"] = "All other values were placeholders"
                
                metadata_values = filtered_metadata
            
            # If no metadata values after filtering, return error
            if not metadata_values:
                logger.warning(f"No valid metadata found for file {file_name} ({file_id}) after filtering")
                return {
                    "file_id": file_id,
                    "file_name": file_name,
                    "success": False,
                    "error": "No valid metadata found after filtering placeholders"
                }
            
            # Normalize keys if requested
            if normalize_keys:
                normalized_metadata = {}
                for key, value in metadata_values.items():
                    # Convert to lowercase and replace spaces with underscores
                    normalized_key = key.lower().replace(" ", "_").replace("-", "_")
                    normalized_metadata[normalized_key] = value
                metadata_values = normalized_metadata
            
            # Convert all values to strings for Box metadata
            for key, value in metadata_values.items():
                if not isinstance(value, (str, int, float, bool)):
                    metadata_values[key] = str(value)
            
            # Debug logging
            logger.info(f"Applying metadata for file: {file_name} ({file_id})")
            logger.info(f"Metadata values after normalization: {json.dumps(metadata_values, default=str)}")
            
            # Get file object
            file_obj = client.file(file_id=file_id)
            
            # Check if we're using structured extraction with a template
            if "metadata_config" in st.session_state and st.session_state.metadata_config.get("extraction_method") == "structured" and st.session_state.metadata_config.get("use_template"):
                # --- BEGIN NEW CODE (Template Selection Logic) ---
                # Get the document type to template mapping from session state
                doc_type_mapping = st.session_state.get("document_type_to_template", {})
                # Get the specific template ID based on the document type
                specific_template_id = doc_type_mapping.get(doc_type)

                # Get the default template ID from config
                default_template_id = st.session_state.metadata_config.get("template_id", "")

                # Use the specific template ID if found, otherwise fall back to default
                if specific_template_id:
                    template_id = specific_template_id
                    logger.info(f"Using specific template 	'{template_id}	' mapped for document type 	'{doc_type}	'")
                else:
                    template_id = default_template_id
                    logger.warning(f"No specific template mapping found for document type 	'{doc_type}	'. Falling back to default template 	'{template_id}	'")

                if not template_id:
                    logger.error(f"No template ID found (neither specific nor default) for file {file_name} ({file_id}). Cannot apply template metadata.")
                    return {
                        "file_id": file_id,
                        "file_name": file_name,
                        "success": False,
                        "error": "No template ID configured or mapped for this document type."
                    }
                # --- END NEW CODE (Template Selection Logic) ---

                # Parse the template ID to extract the correct components
                # Format is typically: scope_templateKey (e.g., enterprise_financialReport or enterprise_12345_myTemplate)
                # We need to handle both formats potentially
                parts = template_id.split('_')
                if len(parts) >= 2:
                    scope = parts[0]
                    template_key = '_'.join(parts[1:]) # Join the rest as the key might contain underscores
                    # If the scope looks like 'enterprise_12345', adjust scope and key
                    if scope.startswith('enterprise') and len(parts) > 2 and parts[1].isdigit():
                         scope = f"{parts[0]}_{parts[1]}"
                         template_key = '_'.join(parts[2:])
                    scope_with_id = scope # Use the potentially adjusted scope
                else:
                    # Fallback if format is unexpected
                    logger.error(f"Unexpected template ID format: {template_id}. Cannot parse scope and key.")
                    return {
                        "file_id": file_id,
                        "file_name": file_name,
                        "success": False,
                        "error": f"Invalid template ID format: {template_id}"
                    }

                logger.info(f"Using template-based metadata application with scope: {scope_with_id}, template: {template_key}")
                try:
                    # ENHANCED FIX: Step 1 - Fix metadata format by converting string representations to dictionaries
                    formatted_metadata = fix_metadata_format(metadata_values)
                    logger.info(f"Formatted metadata after fix_metadata_format: {json.dumps(formatted_metadata, default=str)}")
                    
                    # ENHANCED FIX: Step 2 - Flatten metadata structure to match template requirements
                    flattened_metadata = flatten_metadata_for_template(formatted_metadata)
                    logger.info(f"Flattened metadata after flatten_metadata_for_template: {json.dumps(flattened_metadata, default=str)}")
                    
                        # --- BEGIN NEW CODE ---
                        # Get the template schema from session state
                        template_schemas = st.session_state.get("metadata_templates", {})
                        # Assuming template_id from session state is the full key like 'enterprise_123_myTemplate'
                        template_full_id = template_id

                        if template_full_id not in template_schemas:
                            logger.error(f"Template schema for {template_full_id} not found in session state. Cannot filter fields.")
                            raise ValueError(f"Schema for template {template_full_id} not found in session state.")

                        template_schema = template_schemas[template_full_id]
                        valid_field_keys = {field["key"] for field in template_schema.get("fields", [])}
                        logger.info(f"Valid field keys for template {template_full_id}: {valid_field_keys}")

                        # Filter flattened_metadata to include only keys present in the template schema
                        filtered_metadata = {
                            key: value for key, value in flattened_metadata.items()
                            if key in valid_field_keys
                        }

                        if not filtered_metadata:
                            logger.warning(f"No valid fields found for template {template_full_id} after filtering metadata for file {file_name} ({file_id}). Skipping application.")
                            return {
                                "file_id": file_id,
                                "file_name": file_name,
                                "success": False,
                                "error": f"No metadata fields matched the template schema {template_full_id}."
                            }

                        logger.info(f"Filtered metadata matching template schema: {json.dumps(filtered_metadata, default=str)}")
                        # --- END NEW CODE ---

                        # Log the filtered metadata being sent to Box API
                        logger.info(f"Sending filtered metadata to Box API: {json.dumps(filtered_metadata, default=str)}") # Changed from flattened_metadata

                        # Apply metadata using the template with properly formatted and filtered metadata
                        metadata = file_obj.metadata(scope_with_id, template_key).create(filtered_metadata) # Changed from flattened_metadataa)
                    logger.info(f"Successfully applied template metadata to file {file_name} ({file_id})")
                    return {
                        "file_id": file_id,
                        "file_name": file_name,
                        "success": True,
                        "metadata": metadata
                    }
                except Exception as e:
                    if "already exists" in str(e).lower():
                        # If metadata already exists, update it
                        try:
                            # ENHANCED FIX: Step 1 - Fix metadata format by converting string representations to dictionaries
                            formatted_metadata = fix_metadata_format(metadata_values)
                            logger.info(f"Formatted metadata after fix_metadata_format (update path): {json.dumps(formatted_metadata, default=str)}")
                            
                            # ENHANCED FIX: Step 2 - Flatten metadata structure to match template requirements
                            flattened_metadata = flatten_metadata_for_template(formatted_metadata)
                            logger.info(f"Flattened metadata after flatten_metadata_for_template (update path): {json.dumps(flattened_metadata, default=str)}")
                            
                             # --- BEGIN NEW CODE (Update Path) ---
                            # Get the template schema from session state
                            template_schemas = st.session_state.get("metadata_templates", {})
                            template_full_id = template_id

                            if template_full_id not in template_schemas:
                                logger.error(f"Template schema for {template_full_id} not found in session state (update path). Cannot filter fields.")
                                raise ValueError(f"Schema for template {template_full_id} not found in session state (update path).")

                            template_schema = template_schemas[template_full_id]
                            valid_field_keys = {field["key"] for field in template_schema.get("fields", [])}
                            logger.info(f"Valid field keys for template {template_full_id} (update path): {valid_field_keys}")

                            # Filter flattened_metadata to include only keys present in the template schema
                            filtered_metadata = {
                                key: value for key, value in flattened_metadata.items()
                                if key in valid_field_keys
                            }

                            if not filtered_metadata:
                                logger.warning(f"No valid fields found for template {template_full_id} after filtering metadata for file {file_name} ({file_id}) (update path). Skipping update.")
                                return {
                                    "file_id": file_id,
                                    "file_name": file_name,
                                    "success": False,
                                    "error": f"No metadata fields matched the template schema {template_full_id} during update."
                                }

                            logger.info(f"Filtered metadata matching template schema (update path): {json.dumps(filtered_metadata, default=str)}")
                            # --- END NEW CODE (Update Path) ---

                            # Log the filtered metadata being sent to Box API
                            logger.info(f"Updating with filtered metadata: {json.dumps(filtered_metadata, default=str)}") # Changed from flattened_metadata

                            # Create update operations with filtered metadata
                            operations = []
                            for key, value in filtered_metadata.items(): # Changed from flattened_metadata
                                operations.append({
                                    "op": "replace",
                                    "path": f"/{key}",
                                    "value": value
                                })                         })
                            
                            # Update metadata
                            logger.info(f"Template metadata already exists, updating with operations: {json.dumps(operations, default=str)}")
                            metadata = file_obj.metadata(scope_with_id, template_key).update(operations)
                            
                            logger.info(f"Successfully updated template metadata for file {file_name} ({file_id})")
                            return {
                                "file_id": file_id,
                                "file_name": file_name,
                                "success": True,
                                "metadata": metadata
                            }
                        except Exception as update_error:
                            logger.error(f"Error updating template metadata for file {file_name} ({file_id}): {str(update_error)}")
                            return {
                                "file_id": file_id,
                                "file_name": file_name,
                                "success": False,
                                "error": f"Error updating template metadata: {str(update_error)}"
                            }
                    else:
                        logger.error(f"Error creating template metadata for file {file_name} ({file_id}): {str(e)}")
                        return {
                            "file_id": file_id,
                            "file_name": file_name,
                            "success": False,
                            "error": f"Error creating template metadata: {str(e)}"
                        }
            else:
                # For non-template metadata (freeform), apply as properties
                try:
                    # Apply metadata as properties
                    metadata = file_obj.metadata("global", "properties").create(metadata_values)
                    logger.info(f"Successfully applied metadata to file {file_name} ({file_id})")
                    return {
                        "file_id": file_id,
                        "file_name": file_name,
                        "success": True,
                        "metadata": metadata
                    }
                except Exception as e:
                    if "already exists" in str(e).lower():
                        # If metadata already exists, update it
                        try:
                            # Create update operations
                            operations = []
                            for key, value in metadata_values.items():
                                operations.append({
                                    "op": "replace",
                                    "path": f"/{key}",
                                    "value": value
                                })
                            
                            # Update metadata
                            logger.info(f"Metadata already exists, updating with operations")
                            metadata = file_obj.metadata("global", "properties").update(operations)
                            
                            logger.info(f"Successfully updated metadata for file {file_name} ({file_id})")
                            return {
                                "file_id": file_id,
                                "file_name": file_name,
                                "success": True,
                                "metadata": metadata
                            }
                        except Exception as update_error:
                            logger.error(f"Error updating metadata for file {file_name} ({file_id}): {str(update_error)}")
                            return {
                                "file_id": file_id,
                                "file_name": file_name,
                                "success": False,
                                "error": f"Error updating metadata: {str(update_error)}"
                            }
                    else:
                        logger.error(f"Error creating metadata for file {file_name} ({file_id}): {str(e)}")
                        return {
                            "file_id": file_id,
                            "file_name": file_name,
                            "success": False,
                            "error": f"Error creating metadata: {str(e)}"
                        }
        
        except Exception as e:
            logger.exception(f"Unexpected error applying metadata to file {file_id}: {str(e)}")
            return {
                "file_id": file_id,
                "file_name": file_id_to_file_name.get(file_id, "Unknown"),
                "success": False,
                "error": f"Unexpected error: {str(e)}"
            }
    
    # Handle apply button click - DIRECT APPROACH WITHOUT THREADING
    if apply_button:
        # Check if client exists directly again
        if 'client' not in st.session_state:
            st.error("Box client not found. Please authenticate first.")
            return
        
        # Get client directly
        client = st.session_state.client
        
        # Process files one by one
        results = []
        errors = []
        
        # Create a progress bar
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Process each file
        for i, file_id in enumerate(available_file_ids):
            file_name = file_id_to_file_name.get(file_id, "Unknown")
            status_text.text(f"Processing {file_name}...")
            
            # Get metadata for this file
            metadata_values = file_id_to_metadata.get(file_id, {})
            
            # CRITICAL FIX: Log the metadata values before application
            logger.info(f"Metadata values for file {file_name} ({file_id}) before application: {json.dumps(metadata_values, default=str)}")
            
            # Get document type for mapping
            categorization_results = st.session_state.get("document_categorization", {}).get("results", {})
            # Use str(file_id) for lookup consistency
            doc_type = categorization_results.get(str(file_id), {}).get("category", "Other") # Default to 'Other'
            logger.info(f"Retrieved document type 	'{doc_type}	' for file {file_id}")

            # Apply metadata directly, passing the document type
            result = apply_metadata_to_file_direct(client, file_id, metadata_values, doc_type)
            
            if result["success"]:
                results.append(result)
            else:
                errors.append(result)
            
            # Update progress
            progress = (i + 1) / len(available_file_ids)
            progress_bar.progress(progress)
        
        # Clear progress indicators
        progress_bar.empty()
        status_text.empty()
        
        # Show results
        st.subheader("Metadata Application Results")
        st.write(f"Successfully applied metadata to {len(results)} of {len(available_file_ids)} files.")
        
        if errors:
            with st.expander("View Errors"):
                for error in errors:
                    st.write(f"**{error['file_name']}:** {error['error']}")
        
        if results:
            with st.expander("View Results"):
                for result in results:
                    st.write(f"**{result['file_name']}:** Metadata applied successfully")
    
    # Handle cancel button click
    if cancel_button:
        st.session_state.current_page = "Home"
        st.rerun()
