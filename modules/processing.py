import streamlit as st
import time
import logging
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import List, Dict, Any, Optional, Tuple
import json
import concurrent.futures
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
from .metadata_extraction import get_extraction_functions
from .direct_metadata_application_v3_fixed import apply_metadata_to_file_direct_worker, parse_template_id, get_template_schema

def get_template_id_for_file(file_id: str, file_doc_type: Optional[str], session_state: Dict[str, Any]) -> Optional[str]:
    """Determines the template ID for a file based on config and categorization."""
    metadata_config = session_state.get('metadata_config', {})
    extraction_method = metadata_config.get('extraction_method', 'freeform')

    if extraction_method == 'structured':
        # Correctly access document_type_to_template from the main session_state
        document_type_to_template_mapping = session_state.get('document_type_to_template', {})
        if file_doc_type and document_type_to_template_mapping:
            mapped_template_id = document_type_to_template_mapping.get(file_doc_type)
            if mapped_template_id:
                logger.info(f'File ID {file_id} (type {file_doc_type}): Using mapped template {mapped_template_id}')
                return mapped_template_id
        
        global_structured_template_id = metadata_config.get('template_id')
        if global_structured_template_id:
            logger.info(f'File ID {file_id}: No specific mapping for type {file_doc_type}. Using global structured template {global_structured_template_id}')
            return global_structured_template_id
        
        logger.warning(f'File ID {file_id}: No template ID found for structured extraction/application (no mapping for type {file_doc_type} and no global template).')
        return None
    elif extraction_method == 'freeform':
        # For freeform, a specific template ID might not be relevant in the same way,
        # but if the logic expects one (e.g., 'global_properties'), it's handled here.
        logger.info(f"File ID {file_id}: Using 'global_properties' for freeform (as per existing logic).")
        return 'global_properties' # This was the existing behavior for freeform
    return None

def get_fields_for_ai_from_template(client: Any, scope: str, template_key: str) -> Optional[List[Dict[str, Any]]]:
    """Fetches template schema and formats fields for the AI extraction API."""
    schema = get_template_schema(client, scope, template_key)
    if schema:
        ai_fields = []
        for field_key, field_type in schema.items():
            # Ensure display name is reasonably formatted if not explicitly provided by schema
            display_name = field_key.replace('_', ' ').title()
            ai_fields.append({'key': field_key, 'type': field_type, 'displayName': display_name})
        return ai_fields
    return None

def process_files_with_progress(files_to_process: List[Dict[str, Any]], extraction_functions: Dict[str, Any], batch_size: int, processing_mode: str):
    """
    Processes files, calling the appropriate extraction function with targeted template info.
    Updates st.session_state.extraction_results and st.session_state.processing_state.
    """
    total_files = len(files_to_process)
    st.session_state.processing_state['total_files'] = total_files
    processed_count = 0
    client = st.session_state.client
    metadata_config = st.session_state.get('metadata_config', {})
    ai_model = metadata_config.get('ai_model', 'azure__openai__gpt_4o_mini') # Default model

    for i, file_data in enumerate(files_to_process):
        if not st.session_state.processing_state.get('is_processing', False):
            logger.info('Processing cancelled by user during extraction.')
            break
        
        file_id = str(file_data['id'])
        file_name = file_data.get('name', f'File {file_id}')
        st.session_state.processing_state['current_file_index'] = i
        st.session_state.processing_state['current_file'] = file_name
        logger.info(f'Starting extraction for file {i + 1}/{total_files}: {file_name} (ID: {file_id})')

        current_doc_type = None
        # Check for document categorization results directly in session_state
        categorization_results = st.session_state.get('document_categorization', {}).get('results', {}) # Corrected to get nested results
        cat_result = categorization_results.get(file_id)
        if cat_result:
            current_doc_type = cat_result.get('document_type')

        extraction_method = metadata_config.get('extraction_method', 'freeform')
        extract_func = extraction_functions.get(extraction_method)

        if not extract_func:
            err_msg = f'No extraction function found for method {extraction_method}. Skipping file {file_name}.'
            logger.error(err_msg)
            st.session_state.processing_state['errors'][file_id] = err_msg
            processed_count += 1
            st.session_state.processing_state['processed_files'] = processed_count
            continue

        try:
            extracted_metadata = None
            if extraction_method == 'structured':
                # Pass the main st.session_state to get_template_id_for_file
                target_template_id = get_template_id_for_file(file_id, current_doc_type, st.session_state)
                if target_template_id:
                    try:
                        ext_scope, ext_template_key = parse_template_id(target_template_id)
                        fields_for_ai = get_fields_for_ai_from_template(client, ext_scope, ext_template_key)
                        if fields_for_ai:
                            logger.info(f'File {file_name}: Extracting structured data using template {target_template_id} with fields: {fields_for_ai}')
                            extracted_metadata = extract_func(client=client, file_id=file_id, fields=fields_for_ai, ai_model=ai_model)
                        else:
                            err_msg = f'Could not get fields for template {target_template_id}. Skipping extraction for {file_name}.'
                            logger.error(err_msg)
                            st.session_state.processing_state['errors'][file_id] = err_msg
                    except ValueError as e_parse:
                        err_msg = f'Invalid template ID format {target_template_id} for extraction: {e_parse}. Skipping {file_name}.'
                        logger.error(err_msg)
                        st.session_state.processing_state['errors'][file_id] = err_msg
                else:
                    err_msg = f'No target template ID determined for structured extraction for file {file_name}. Skipping.'
                    logger.error(err_msg)
                    st.session_state.processing_state['errors'][file_id] = err_msg
            
            elif extraction_method == 'freeform':
                # Get document-specific prompt if available, otherwise global prompt
                doc_specific_prompts = metadata_config.get('document_type_prompts', {})
                prompt_to_use = metadata_config.get('freeform_prompt', 'Extract key information.') # Default global prompt
                if current_doc_type and current_doc_type in doc_specific_prompts:
                    prompt_to_use = doc_specific_prompts[current_doc_type]
                    logger.info(f'File {file_name} (type {current_doc_type}): Using specific freeform prompt.')
                else:
                    logger.info(f'File {file_name}: Using global freeform prompt.')
                
                logger.info(f'File {file_name}: Extracting freeform data with prompt: {prompt_to_use}')
                extracted_metadata = extract_func(client=client, file_id=file_id, prompt=prompt_to_use, ai_model=ai_model)

            if extracted_metadata:
                # Check for API errors returned in the metadata itself
                if isinstance(extracted_metadata, dict) and 'error' in extracted_metadata:
                    err_msg = f"Error from extraction API for {file_name}: {extracted_metadata['error']}"
                    logger.error(err_msg)
                    st.session_state.processing_state['errors'][file_id] = err_msg
                else:
                    st.session_state.extraction_results[file_id] = {
                        "ai_response": extracted_metadata,
                        "template_id_used_for_extraction": target_template_id if extraction_method == "structured" else "global_properties"
                    }
                    st.session_state.processing_state["results"][file_id] = extracted_metadata # Keep this for immediate UI, but application will use the above structure
                    logger.info(f'Successfully extracted metadata for {file_name} (ID: {file_id})') # Avoid logging potentially large metadata here
            elif file_id not in st.session_state.processing_state['errors']:
                st.session_state.processing_state['errors'][file_id] = 'Extraction returned no data and no specific error.'
                logger.warning(f'Extraction returned no data for {file_name} (ID: {file_id}).')

        except Exception as e_extract:
            err_msg = f'Error during metadata extraction for {file_name} (ID: {file_id}): {str(e_extract)}'
            logger.error(err_msg, exc_info=True)
            st.session_state.processing_state['errors'][file_id] = err_msg
        
        processed_count += 1
        st.session_state.processing_state['processed_files'] = processed_count

    st.session_state.processing_state['is_processing'] = False
    logger.info('Metadata extraction process finished for all selected files.')
    st.rerun()

def process_files():
    """
    Main Streamlit page function for processing files.
    Handles UI, configuration, and orchestrates extraction and application.
    """
    st.title('Process Files')

    # Initialize necessary session state variables if they don't exist
    if 'debug_info' not in st.session_state: st.session_state.debug_info = []
    if 'metadata_templates' not in st.session_state: st.session_state.metadata_templates = {}
    if 'feedback_data' not in st.session_state: st.session_state.feedback_data = {}
    if 'extraction_results' not in st.session_state: st.session_state.extraction_results = {}
    if 'document_categorization_results' not in st.session_state: st.session_state.document_categorization_results = {}
    if 'processing_state' not in st.session_state:
        st.session_state.processing_state = {
            'is_processing': False, 'processed_files': 0, 
            'total_files': len(st.session_state.get('selected_files', [])),
            'current_file_index': -1, 'current_file': '', 
            'results': {}, 'errors': {}, 'retries': {}, 
            'max_retries': 3, 'retry_delay': 2, 
            'visualization_data': {}, 'metadata_applied_status': {}
        }

    try:
        if not st.session_state.get('authenticated') or not st.session_state.get('client'):
            st.error('Please authenticate with Box first.')
            if st.button('Go to Login'):
                st.session_state.current_page = 'Home'
                st.rerun()
            return

        client = st.session_state.client # Ensure client is available

        if not st.session_state.get('selected_files'):
            st.warning('No files selected. Please select files in the File Browser first.')
            if st.button('Go to File Browser', key='go_to_file_browser_button_proc'):
                st.session_state.current_page = 'File Browser'
                st.rerun()
            return

        metadata_config_state = st.session_state.get('metadata_config', {})
        # Check if structured extraction is chosen but no global template is set (custom fields are not yet fully supported for extraction part)
        is_structured_incomplete = (
            metadata_config_state.get('extraction_method') == 'structured' and 
            not metadata_config_state.get('template_id') and 
            not any(st.session_state.get('document_type_to_template', {}).values()) # Check if any per-type mapping exists
        )

        if not metadata_config_state or (metadata_config_state.get('extraction_method') == 'structured' and not metadata_config_state.get('template_id') and not any(st.session_state.get('document_type_to_template',{}).values())):
            st.warning('Metadata configuration is incomplete. For structured extraction, please ensure a global template is selected or document types are mapped to templates.')
            if st.button('Go to Metadata Configuration', key='go_to_metadata_config_button_proc'):
                st.session_state.current_page = 'Metadata Configuration'
                st.rerun()
            return

        st.write(f"Ready to process {len(st.session_state.selected_files)} files.")

        with st.expander('Batch Processing Controls'):
            col1, col2 = st.columns(2)
            with col1:
                batch_size = st.number_input('Batch Size', min_value=1, max_value=50, value=metadata_config_state.get('batch_size', 5), key='batch_size_input_proc')
                st.session_state.metadata_config['batch_size'] = batch_size # Update config directly
                max_retries = st.number_input('Max Retries', min_value=0, max_value=10, value=st.session_state.processing_state.get('max_retries', 3), key='max_retries_input_proc')
                st.session_state.processing_state['max_retries'] = max_retries
            with col2:
                retry_delay = st.number_input('Retry Delay (s)', min_value=1, max_value=30, value=st.session_state.processing_state.get('retry_delay', 2), key='retry_delay_input_proc')
                st.session_state.processing_state['retry_delay'] = retry_delay
                processing_mode = st.selectbox('Processing Mode', options=['Sequential', 'Parallel'], index=0, key='processing_mode_input_proc', help='Parallel processing is experimental.')
                st.session_state.processing_state['processing_mode'] = processing_mode
        
        auto_apply_metadata = st.checkbox('Automatically apply metadata after extraction', value=st.session_state.processing_state.get('auto_apply_metadata', True), key='auto_apply_metadata_checkbox_proc')
        st.session_state.processing_state['auto_apply_metadata'] = auto_apply_metadata

        col_start, col_cancel = st.columns(2)
        with col_start:
            start_button = st.button('Start Processing', disabled=st.session_state.processing_state.get('is_processing', False), use_container_width=True, key='start_processing_button_proc')
        with col_cancel:
            cancel_button = st.button('Cancel Processing', disabled=not st.session_state.processing_state.get('is_processing', False), use_container_width=True, key='cancel_processing_button_proc')

        progress_bar_placeholder = st.empty()
        status_text_placeholder = st.empty()

        if start_button:
            st.session_state.processing_state.update({
                'is_processing': True, 'processed_files': 0, 
                'total_files': len(st.session_state.selected_files),
                'current_file_index': -1, 'current_file': '', 
                'results': {}, 'errors': {}, 'retries': {},
                'max_retries': max_retries, 'retry_delay': retry_delay, 
                'processing_mode': processing_mode, 
                'auto_apply_metadata': auto_apply_metadata,
                'visualization_data': {}, 'metadata_applied_status': {}
            })
            st.session_state.extraction_results = {} # Clear previous overall results
            logger.info('Starting file processing orchestration...')
            # Call the processing function
            process_files_with_progress(
                st.session_state.selected_files, 
                get_extraction_functions(), 
                batch_size=batch_size, 
                processing_mode=processing_mode
            )
            # Note: process_files_with_progress will call st.rerun() itself upon completion/cancellation

        if cancel_button and st.session_state.processing_state.get('is_processing', False):
            st.session_state.processing_state['is_processing'] = False
            logger.info('Processing cancelled by user via button.')
            status_text_placeholder.warning('Processing cancelled.')
            st.rerun() # Rerun to reflect cancelled state

        current_processing_state = st.session_state.processing_state
        if current_processing_state.get('is_processing', False):
            processed_files_count = current_processing_state['processed_files']
            total_files_count = current_processing_state['total_files']
            current_file_name = current_processing_state['current_file']
            progress_value = (processed_files_count / total_files_count) if total_files_count > 0 else 0
            progress_bar_placeholder.progress(progress_value)
            status_text_placeholder.text(f'Processing {current_file_name}... ({processed_files_count}/{total_files_count})' if current_file_name else f'Processed {processed_files_count}/{total_files_count} files')
        
        # Display results summary only if not currently processing and some processing has occurred
        elif not current_processing_state.get('is_processing', False) and current_processing_state.get('total_files', 0) > 0 and current_processing_state.get('processed_files', 0) == current_processing_state.get('total_files',0):
            processed_files_count = current_processing_state.get('processed_files', 0)
            total_files_count = current_processing_state.get('total_files', 0)
            successful_extractions_count = len(current_processing_state.get('results', {}))
            extraction_error_count = len(current_processing_state.get('errors', {}))

            if total_files_count > 0:
                if successful_extractions_count == total_files_count and extraction_error_count == 0:
                    st.success(f'Extraction complete! Successfully processed {successful_extractions_count} files.')
                elif successful_extractions_count > 0:
                    st.warning(f'Extraction complete! Processed {successful_extractions_count} files successfully, with {extraction_error_count} errors on other files.')
                elif extraction_error_count > 0:
                    st.error(f'Extraction failed for {extraction_error_count} files. No files successfully processed.')
                else: # Should not happen if total_files > 0 and processed_files == total_files
                    st.info("Processing finished, but no results or errors were recorded.")

                if current_processing_state.get('errors'):
                    with st.expander('View Extraction Errors', expanded=True if extraction_error_count > 0 else False):
                        error_data = []
                        for file_id_err, error_msg_err in current_processing_state['errors'].items():
                            file_name_err = 'Unknown File'
                            for f_info in st.session_state.selected_files:
                                if str(f_info.get('id')) == str(file_id_err):
                                    file_name_err = f_info.get('name', f'File ID {file_id_err}')
                                    break
                            error_data.append({'File Name': file_name_err, 'Error': error_msg_err, 'File ID': file_id_err})
                        if error_data:
                            st.table(pd.DataFrame(error_data))
                        else:
                            st.write("No extraction errors recorded.")
            
            # Visualization of results (example)
            if successful_extractions_count > 0 or extraction_error_count > 0:
                st.subheader("Extraction Summary")
                labels = 'Successful', 'Failed'
                sizes = [successful_extractions_count, extraction_error_count]
                colors = ['#4CAF50', '#F44336'] # Green for success, Red for failure
                explode = (0.1, 0) if successful_extractions_count > 0 and extraction_error_count > 0 else (0,0)

                fig1, ax1 = plt.subplots()
                ax1.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
                        shadow=True, startangle=90)
                ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
                st.pyplot(fig1)

    except Exception as e:
        logger.error(f"An unexpected error occurred in the Process Files page: {e}", exc_info=True)
        st.error(f"An unexpected error occurred: {e}")
        # Optionally add a button to reset state or navigate away
        if st.button("Reset and Go Home"):
            # Clear potentially problematic state variables
            for key_to_clear in ['processing_state', 'extraction_results']:
                if key_to_clear in st.session_state:
                    del st.session_state[key_to_clear]
            st.session_state.current_page = "Home"
            st.rerun()

