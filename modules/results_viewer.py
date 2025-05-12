import streamlit as st
import pandas as pd
from typing import Dict, List, Any
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_confidence_color(confidence_level):
    """Get color based on confidence level."""
    if confidence_level == 'High':
        return 'green'
    elif confidence_level == 'Medium':
        return 'orange'
    elif confidence_level == 'Low':
        return 'red'
    else:
        return 'gray'

def view_results():
    """
    View and manage extraction results.
    Handles the new structure in st.session_state.extraction_results where each item is a dict
    with "ai_response" and "template_id_used_for_extraction".
    """
    st.title('View Results')

    #region Session State Initializations
    if not hasattr(st.session_state, 'authenticated') or not hasattr(st.session_state, 'client') or \
       (not st.session_state.authenticated) or (not st.session_state.client):
        st.error('Please authenticate with Box first')
        return

    if not hasattr(st.session_state, 'extraction_results'):
        st.session_state.extraction_results = {}
        logger.info('Initialized extraction_results in view_results')

    if not hasattr(st.session_state, 'selected_result_ids'):
        st.session_state.selected_result_ids = []
        logger.info('Initialized selected_result_ids in view_results')

    if not hasattr(st.session_state, 'metadata_config'):
        st.session_state.metadata_config = {
            'extraction_method': 'freeform', 
            'freeform_prompt': 'Extract key metadata from this document.', 
            'use_template': False, 
            'template_id': '', 
            'custom_fields': [], 
            'ai_model': 'azure__openai__gpt_4o_mini', 
            'batch_size': 5
        }
        logger.info('Initialized metadata_config in view_results')
    #endregion

    if not st.session_state.extraction_results:
        st.warning('No extraction results available. Please process files first.')
        if st.button('Go to Process Files', key='go_to_process_files_btn_vr'):
            st.session_state.current_page = 'Process Files'
            st.rerun()
        return

    st.write('Review and manage the metadata extraction results.')

    #region Filters Initialization
    if not hasattr(st.session_state, 'results_filter_text'): # Renamed to avoid conflict if old key exists
        st.session_state.results_filter_text = ''
    if not hasattr(st.session_state, 'confidence_filter_selection'): # Renamed
        st.session_state.confidence_filter_selection = ['High', 'Medium', 'Low']
    #endregion

    st.subheader('Filter Results')
    col1_filter, col2_filter = st.columns(2)
    with col1_filter:
        st.session_state.results_filter_text = st.text_input('Filter by file name', value=st.session_state.results_filter_text, key='filter_text_input_vr')
    with col2_filter:
        st.session_state.confidence_filter_selection = st.multiselect('Filter by Confidence Level', options=['High', 'Medium', 'Low'], default=st.session_state.confidence_filter_selection, key='confidence_filter_multiselect_vr')

    processed_and_filtered_results = {}
    for file_id, result_wrapper in st.session_state.extraction_results.items():
        processed_result_for_file = {
            'file_id': file_id, 
            'file_name': 'Unknown', 
            'result_data': {}, 
            'confidence_levels': {}
        }

        # Get file name
        if hasattr(st.session_state, 'selected_files') and st.session_state.selected_files:
            for file_obj in st.session_state.selected_files:
                if str(file_obj.get('id')) == str(file_id):
                    processed_result_for_file['file_name'] = file_obj.get('name', 'Unknown')
                    break
        
        # Unpack the ai_response from the wrapper
        actual_ai_response = None
        if isinstance(result_wrapper, dict) and "ai_response" in result_wrapper:
            actual_ai_response = result_wrapper["ai_response"]
            # We don't need template_id_used_for_extraction for display here, but it's in result_wrapper
        else:
            logger.warning(f"File ID {file_id}: Item in extraction_results is not the expected wrapper or 'ai_response' is missing. Item: {result_wrapper}")
            actual_ai_response = result_wrapper # Fallback to treat the whole item as the AI response (e.g., if old format)

        logger.info(f'VIEW_RESULTS: Processing AI response for file_id {file_id}: {(json.dumps(actual_ai_response) if isinstance(actual_ai_response, dict) else str(actual_ai_response))}')

        # --- Start of existing parsing logic, now operating on actual_ai_response ---
        if isinstance(actual_ai_response, dict):
            processed_result_for_file['original_data'] = actual_ai_response # Store the AI's direct response

            # Try to parse common AI response structures
            if 'answer' in actual_ai_response:
                answer_content = actual_ai_response['answer']
                if isinstance(answer_content, str):
                    try: answer_content = json.loads(answer_content)
                    except json.JSONDecodeError: pass # Keep as string if not JSON
                
                if isinstance(answer_content, dict):
                    for key, value_obj in answer_content.items():
                        if isinstance(value_obj, dict) and 'value' in value_obj:
                            processed_result_for_file['result_data'][key] = value_obj['value']
                            processed_result_for_file['confidence_levels'][key] = value_obj.get('confidence', 'Medium')
                        else:
                            processed_result_for_file['result_data'][key] = value_obj
                            processed_result_for_file['confidence_levels'][key] = 'Medium'
                else: # Answer is a string or other non-dict type
                    processed_result_for_file['result_data']['extracted_text'] = str(answer_content)
                    processed_result_for_file['confidence_levels']['extracted_text'] = 'Medium'
            
            elif 'items' in actual_ai_response and isinstance(actual_ai_response['items'], list) and actual_ai_response['items']:
                # Handle cases where response is wrapped in 'items' (e.g. some Box AI skill responses)
                item_answer = actual_ai_response['items'][0].get('answer') # Assuming first item's answer
                if item_answer:
                    if isinstance(item_answer, str):
                        try: item_answer = json.loads(item_answer)
                        except json.JSONDecodeError: pass
                    if isinstance(item_answer, dict):
                         for key, value_obj in item_answer.items():
                            if isinstance(value_obj, dict) and 'value' in value_obj:
                                processed_result_for_file['result_data'][key] = value_obj['value']
                                processed_result_for_file['confidence_levels'][key] = value_obj.get('confidence', 'Medium')
                            else:
                                processed_result_for_file['result_data'][key] = value_obj
                                processed_result_for_file['confidence_levels'][key] = 'Medium'
                    else:
                        processed_result_for_file['result_data']['extracted_item_text'] = str(item_answer)
                        processed_result_for_file['confidence_levels']['extracted_item_text'] = 'Medium'
            
            elif any((key.endswith('_confidence') for key in actual_ai_response.keys())):
                # Handle flat structure with explicit _confidence fields
                for key, value in actual_ai_response.items():
                    if key.endswith('_confidence'):
                        base_key = key[:-len('_confidence')]
                        if base_key in actual_ai_response: # Ensure the base key exists
                            processed_result_for_file['result_data'][base_key] = actual_ai_response[base_key]
                            processed_result_for_file['confidence_levels'][base_key] = value
                    elif not any(key == k[:-len('_confidence')] for k in actual_ai_response if k.endswith('_confidence')):
                         # Add fields that don't have a corresponding _confidence field
                        if key not in ['ai_agent_info', 'created_at', 'completion_reason']:
                            processed_result_for_file['result_data'][key] = value
                            processed_result_for_file['confidence_levels'][key] = 'Medium' # Default confidence
            
            # Fallback if no specific structure matched but it's a dict
            if not processed_result_for_file['result_data']:
                logger.info(f"File ID {file_id}: AI response was a dict, but no known structure parsed. Using its keys directly.")
                for key, value in actual_ai_response.items():
                    if key not in ['ai_agent_info', 'created_at', 'completion_reason', 'answer', 'items'] and not key.endswith('_confidence'):
                        processed_result_for_file['result_data'][key] = value
                        processed_result_for_file['confidence_levels'][key] = actual_ai_response.get(f"{key}_confidence", 'Medium')
        
        else: # actual_ai_response is not a dict (e.g., a string from a simple AI text_gen)
            logger.warning(f'File ID {file_id}: AI response is not a dictionary: {type(actual_ai_response)}. Displaying as raw text.')
            processed_result_for_file['result_data']['extracted_text'] = str(actual_ai_response)
            processed_result_for_file['confidence_levels']['extracted_text'] = 'Medium'
        # --- End of existing parsing logic ---

        # Apply filters
        name_match = st.session_state.results_filter_text.lower() in processed_result_for_file['file_name'].lower()
        confidence_match = False
        if not st.session_state.confidence_filter_selection: # If no confidence filter, it's a match
            confidence_match = True
        else:
            for conf_level in processed_result_for_file['confidence_levels'].values():
                if conf_level in st.session_state.confidence_filter_selection:
                    confidence_match = True
                    break
        
        if name_match and confidence_match:
            processed_and_filtered_results[file_id] = processed_result_for_file

    # Prepare data for DataFrame
    table_data_for_df = []
    for file_id, data_item in processed_and_filtered_results.items():
        row = {'File Name': data_item['file_name'], 'File ID': file_id}
        for key, value in data_item['result_data'].items():
            row[key] = value
            row[f'{key} Confidence'] = data_item['confidence_levels'].get(key, 'N/A')
        table_data_for_df.append(row)
    
    df_results = pd.DataFrame(table_data_for_df)

    if not df_results.empty:
        base_cols = ['File Name', 'File ID']
        field_cols_sorted = sorted([col for col in df_results.columns if col not in base_cols and not col.endswith(' Confidence')])
        final_ordered_cols = base_cols + [item for field in field_cols_sorted for item in (field, f'{field} Confidence') if item in df_results.columns]
        df_results = df_results[final_ordered_cols]

    st.subheader('Extraction Results')
    tab_table, tab_detailed = st.tabs(['Table View', 'Detailed View'])

    with tab_table:
        st.write(f'Showing {len(df_results)} of {len(st.session_state.extraction_results)} results based on filters.')
        if not df_results.empty:
            st.dataframe(df_results.style.applymap(
                lambda x: f'color: {get_confidence_color(x)}', 
                subset=[col for col in df_results.columns if col.endswith(' Confidence')]
            ), use_container_width=True, hide_index=True)
            
            # Export buttons (functionality not fully implemented here)
            col_export1, col_export2 = st.columns(2)
            with col_export1:
                if st.button('Export as CSV', use_container_width=True, key='export_csv_btn_vr'):
                    st.info('CSV export would be implemented here.') 
            with col_export2:
                if st.button('Export as Excel', use_container_width=True, key='export_excel_btn_vr'):
                    st.info('Excel export would be implemented here.')
        else:
            st.info('No results match the current filter criteria.')

    with tab_detailed:
        if not processed_and_filtered_results:
            st.info('No results to display based on current filters.')
        else:
            detailed_view_file_options = {
                result_item['file_name']: file_id 
                for file_id, result_item in processed_and_filtered_results.items()
            }
            selected_file_name_for_detail = st.selectbox(
                'Select a file to view details:', 
                options=list(detailed_view_file_options.keys()),
                key='detailed_view_select_vr'
            )

            if selected_file_name_for_detail:
                selected_file_id_for_detail = detailed_view_file_options[selected_file_name_for_detail]
                detailed_data = processed_and_filtered_results[selected_file_id_for_detail]
                st.write(f"**File Name:** {detailed_data['file_name']}")
                st.write(f"**File ID:** {detailed_data['file_id']}")
                st.write("**Extracted Metadata:**")
                for key, value in detailed_data['result_data'].items():
                    confidence = detailed_data['confidence_levels'].get(key, 'N/A')
                    st.text_input(f"{key} (Confidence: {confidence})", value=str(value), key=f'detail_{selected_file_id_for_detail}_{key}', disabled=True)
                
                # Display raw AI response if available
                if 'original_data' in detailed_data and detailed_data['original_data']:
                    with st.expander("View Raw AI Response"):
                        st.json(detailed_data['original_data'])

    st.subheader('Batch Operations')
    col_select_all, col_deselect_all = st.columns(2)
    with col_select_all:
        if st.button('Select All Displayed', use_container_width=True, key='select_all_btn_vr'):
            st.session_state.selected_result_ids = list(processed_and_filtered_results.keys())
            st.rerun()
    with col_deselect_all:
        if st.button('Deselect All', use_container_width=True, key='deselect_all_btn_vr'):
            st.session_state.selected_result_ids = []
            st.rerun()
    
    st.write(f"Selected {len(st.session_state.selected_result_ids)} of {len(processed_and_filtered_results)} displayed results for metadata application.")

    if st.button('Apply Metadata', use_container_width=True, key='apply_metadata_btn_vr'):
        if not st.session_state.selected_result_ids:
            st.warning('Please select at least one file to apply metadata.')
        else:
            # Ensure the correct function is called for metadata application
            # This part assumes direct_metadata_application_v3_fixed.py is correctly imported in app.py or handled by navigation
            st.session_state.current_page = "Apply Metadata" # Navigate to the application page
            logger.info(f"View Results: Navigating to Apply Metadata page with {len(st.session_state.selected_result_ids)} selected files.")
            st.rerun()


