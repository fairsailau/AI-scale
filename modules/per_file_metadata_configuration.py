import streamlit as st
import pandas as pd
import logging
from typing import Dict, List, Any, Optional
logger = logging.getLogger(__name__)

def render_per_file_metadata_config(selected_files: List[Dict[str, Any]], available_templates: List[Dict[str, Any]]):
    """
    Render the per-file metadata configuration UI component.
    
    Args:
        selected_files: List of selected file objects with id and name
        available_templates: List of available metadata templates
    """
    st.title('Metadata Configuration')
    if not selected_files:
        st.warning('No files selected. Please select files first.')
        return
    st.header('Document Categorization Results')
    file_data = []
    for i, file_info in enumerate(selected_files):
        file_id = file_info.get('id', '')
        file_name = file_info.get('name', 'Unknown')
        doc_type = file_info.get('document_type', 'Unknown')
        file_data.append({'index': i, 'file_id': file_id, 'file_name': file_name, 'document_type': doc_type})
    df = pd.DataFrame(file_data)
    st.dataframe(df[['file_name', 'document_type']], column_config={'file_name': 'File Name', 'document_type': 'Document Type'}, hide_index=True)
    if 'file_metadata_config' not in st.session_state:
        st.session_state.file_metadata_config = {}
    for file_info in selected_files:
        file_id = file_info.get('id', '')
        if file_id and file_id not in st.session_state.file_metadata_config:
            st.session_state.file_metadata_config[file_id] = {'extraction_method': 'structured', 'template_id': '', 'custom_prompt': ''}
    st.header('Per-File Extraction Configuration')
    st.info('Configure extraction method and template for each file individually.')
    file_tabs = st.tabs([f"{file_info.get('name', 'File')} ({i + 1}/{len(selected_files)})" for i, file_info in enumerate(selected_files)])
    for i, (tab, file_info) in enumerate(zip(file_tabs, selected_files)):
        file_id = file_info.get('id', '')
        file_name = file_info.get('name', 'Unknown')
        doc_type = file_info.get('document_type', 'Unknown')
        with tab:
            st.subheader(f'Configuration for: {file_name}')
            st.write(f'Document Type: {doc_type}')
            file_config = st.session_state.file_metadata_config.get(file_id, {})
            extraction_method = st.radio('Select extraction method', options=['Structured', 'Freeform'], index=0 if file_config.get('extraction_method', 'structured') == 'structured' else 1, key=f'extraction_method_{file_id}', horizontal=True)
            file_config['extraction_method'] = extraction_method.lower()
            if extraction_method.lower() == 'structured':
                st.subheader('Structured Extraction Configuration')
                template_options = [''] + [t.get('id', '') for t in available_templates]
                template_labels = ['Select a template...'] + [t.get('displayName', t.get('id', '')) for t in available_templates]
                template_index = 0
                current_template = file_config.get('template_id', '')
                if current_template in template_options:
                    template_index = template_options.index(current_template)
                selected_template = st.selectbox('Select Metadata Template', options=template_options, format_func=lambda x: template_labels[template_options.index(x)] if x in template_options else x, index=template_index, key=f'template_select_{file_id}')
                file_config['template_id'] = selected_template
                file_config['custom_prompt'] = ''
                if selected_template:
                    template_info = next((t for t in available_templates if t.get('id') == selected_template), None)
                    if template_info:
                        st.info(f"Template: {template_info.get('displayName', template_info.get('id', ''))}")
                        fields = template_info.get('fields', [])
                        if fields:
                            st.write('Template Fields:')
                            field_data = []
                            for field in fields:
                                field_data.append({'key': field.get('key', ''), 'displayName': field.get('displayName', field.get('key', '')), 'type': field.get('type', 'string'), 'required': 'Yes' if field.get('hidden', False) else 'No'})
                            st.dataframe(pd.DataFrame(field_data), column_config={'key': 'Field Key', 'displayName': 'Display Name', 'type': 'Type', 'required': 'Required'}, hide_index=True)
            else:
                st.subheader('Freeform Extraction Configuration')
                custom_prompt = st.text_area('Custom Extraction Prompt', value=file_config.get('custom_prompt', ''), height=150, key=f'custom_prompt_{file_id}', help='Enter a custom prompt for extracting metadata from this file.')
                file_config['custom_prompt'] = custom_prompt
                file_config['template_id'] = ''
            st.session_state.file_metadata_config[file_id] = file_config
    st.header('Configuration Summary')
    summary_data = []
    for file_info in selected_files:
        file_id = file_info.get('id', '')
        file_name = file_info.get('name', 'Unknown')
        file_config = st.session_state.file_metadata_config.get(file_id, {})
        extraction_method = file_config.get('extraction_method', 'structured')
        template_id = file_config.get('template_id', '')
        custom_prompt = file_config.get('custom_prompt', '')
        template_name = template_id
        if template_id:
            template_info = next((t for t in available_templates if t.get('id') == template_id), None)
            if template_info:
                template_name = template_info.get('displayName', template_id)
        config_details = template_name if extraction_method == 'structured' else 'Custom prompt'
        summary_data.append({'file_name': file_name, 'extraction_method': extraction_method.capitalize(), 'config_details': config_details})
    st.dataframe(pd.DataFrame(summary_data), column_config={'file_name': 'File Name', 'extraction_method': 'Extraction Method', 'config_details': 'Template/Prompt'}, hide_index=True)
    if st.button('Save Configuration', use_container_width=True):
        st.success('Configuration saved successfully!')
        logger.info(f'Saved per-file metadata configuration for {len(selected_files)} files')
        for file_id, config in st.session_state.file_metadata_config.items():
            logger.info(f'File ID: {file_id}, Config: {config}')
        st.session_state.metadata_config = {'extraction_method': 'per_file', 'use_template': True}

def get_file_specific_config(file_id: str) -> Dict[str, Any]:
    """
    Get the specific metadata configuration for a file.
    
    Args:
        file_id: The ID of the file to get configuration for
        
    Returns:
        Dict containing the file's metadata configuration
    """
    if 'file_metadata_config' not in st.session_state:
        return {'extraction_method': 'structured', 'template_id': '', 'custom_prompt': ''}
    return st.session_state.file_metadata_config.get(file_id, {'extraction_method': 'structured', 'template_id': '', 'custom_prompt': ''})

def process_file_with_specific_config(file_id: str, file_name: str, client: Any) -> Dict[str, Any]:
    """
    Process a file using its specific metadata configuration.
    
    Args:
        file_id: The ID of the file to process
        file_name: The name of the file
        client: Box client object
        
    Returns:
        Dict containing the processing results
    """
    file_config = get_file_specific_config(file_id)
    extraction_method = file_config.get('extraction_method', 'structured')
    logger.info(f'Processing file {file_name} ({file_id}) with {extraction_method} extraction method')
    if extraction_method == 'structured':
        template_id = file_config.get('template_id', '')
        if not template_id:
            logger.warning(f'No template selected for structured extraction of file {file_name} ({file_id})')
            return {'file_id': file_id, 'file_name': file_name, 'success': False, 'error': 'No template selected for structured extraction'}
        logger.info(f'Using template {template_id} for structured extraction of file {file_name} ({file_id})')
    else:
        custom_prompt = file_config.get('custom_prompt', '')
        if not custom_prompt:
            logger.warning(f'No custom prompt provided for freeform extraction of file {file_name} ({file_id})')
            return {'file_id': file_id, 'file_name': file_name, 'success': False, 'error': 'No custom prompt provided for freeform extraction'}
        logger.info(f'Using custom prompt for freeform extraction of file {file_name} ({file_id})')
    return {'file_id': file_id, 'file_name': file_name, 'success': True, 'extraction_method': extraction_method, 'config': file_config}