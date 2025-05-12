import streamlit as st
import logging
import json
from typing import Dict, Any, List, Optional
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def metadata_config():
    """
    Configure metadata extraction parameters
    """
    st.title('Metadata Configuration')
    if not st.session_state.authenticated or not st.session_state.client:
        st.error('Please authenticate with Box first')
        return
    if not st.session_state.selected_files:
        st.warning('No files selected. Please select files in the File Browser first.')
        if st.button('Go to File Browser', key='go_to_file_browser_button_config'):
            st.session_state.current_page = 'File Browser'
            st.rerun()
        return
    has_categorization = hasattr(st.session_state, 'document_categorization') and st.session_state.document_categorization.get('is_categorized', False)
    if has_categorization:
        st.subheader('Document Categorization Results')
        categorization_data = []
        for file in st.session_state.selected_files:
            file_id = file['id']
            file_name = file['name']
            document_type = 'Not categorized'
            if file_id in st.session_state.document_categorization['results']:
                document_type = st.session_state.document_categorization['results'][file_id]['document_type']
            categorization_data.append({'File Name': file_name, 'Document Type': document_type})
        st.table(categorization_data)
    else:
        st.info('Document categorization has not been performed. You can categorize documents in the Document Categorization page.')
        if st.button('Go to Document Categorization', key='go_to_doc_cat_button'):
            st.session_state.current_page = 'Document Categorization'
            st.rerun()
    st.subheader('Extraction Method')
    if 'extraction_method' not in st.session_state.metadata_config:
        st.session_state.metadata_config['extraction_method'] = 'freeform'
    extraction_method_options = ['Freeform', 'Structured']
    current_extraction_method_index = 0 if st.session_state.metadata_config['extraction_method'] == 'freeform' else 1
    extraction_method = st.radio('Select extraction method', extraction_method_options, index=current_extraction_method_index, key='extraction_method_radio', help='Choose between freeform extraction (free text) or structured extraction (with template)')
    new_extraction_method_lower = extraction_method.lower()
    if st.session_state.metadata_config['extraction_method'] != new_extraction_method_lower:
        st.session_state.metadata_config['extraction_method'] = new_extraction_method_lower
        if new_extraction_method_lower == 'freeform':
            st.session_state.metadata_config['template_id'] = 'global_properties'
            st.session_state.metadata_config['use_template'] = True
            logger.info("Extraction method changed to Freeform. Defaulting template_id to 'global_properties'.")
        else:
            st.session_state.metadata_config['template_id'] = ''
            st.session_state.metadata_config['use_template'] = False
            logger.info('Extraction method changed to Structured. User needs to select a template.')
    if st.session_state.metadata_config['extraction_method'] == 'freeform':
        st.subheader('Freeform Extraction Configuration')
        if st.session_state.metadata_config.get('template_id') != 'global_properties':
            st.session_state.metadata_config['template_id'] = 'global_properties'
            st.session_state.metadata_config['use_template'] = True
            logger.info("Ensured template_id is 'global_properties' for Freeform extraction method.")
        st.caption('Freeform extraction will use the `global_properties` metadata template by default.')
        freeform_prompt = st.text_area('Freeform prompt', value=st.session_state.metadata_config.get('freeform_prompt', 'Extract key metadata from this document including dates, names, amounts, and other important information.'), height=150, key='freeform_prompt_textarea', help='Prompt for freeform extraction. Be specific about what metadata to extract.')
        st.session_state.metadata_config['freeform_prompt'] = freeform_prompt
        if has_categorization:
            st.subheader('Document Type Specific Prompts')
            st.info('You can customize the freeform prompt for each document type.')
            document_types = set()
            for file_id, result in st.session_state.document_categorization['results'].items():
                document_types.add(result['document_type'])
            if 'document_type_prompts' not in st.session_state.metadata_config:
                st.session_state.metadata_config['document_type_prompts'] = {}
            for doc_type in document_types:
                current_prompt = st.session_state.metadata_config['document_type_prompts'].get(doc_type, st.session_state.metadata_config['freeform_prompt'])
                doc_type_prompt = st.text_area(f'Prompt for {doc_type}', value=current_prompt, height=100, key=f"prompt_{doc_type.replace(' ', '_').lower()}", help=f'Customize the prompt for {doc_type} documents')
                st.session_state.metadata_config['document_type_prompts'][doc_type] = doc_type_prompt
    else:
        st.subheader('Structured Extraction Configuration')
        if not hasattr(st.session_state, 'metadata_templates') or not st.session_state.metadata_templates:
            st.warning('No metadata templates available. Please refresh templates in the sidebar.')
            return
        templates = st.session_state.metadata_templates
        template_options = [('', 'None - Use custom fields')]
        for template_id, template in templates.items():
            template_options.append((template_id, template['displayName']))
        st.write('#### Select Metadata Template')
        if has_categorization:
            st.subheader('Document Type Template Mapping')
            st.info('You can map each document type to a specific metadata template.')
            document_types = set()
            for file_id, result in st.session_state.document_categorization['results'].items():
                document_types.add(result['document_type'])
            if not hasattr(st.session_state, 'document_type_to_template'):
                from modules.metadata_template_retrieval import initialize_template_state
                initialize_template_state()
            for doc_type in document_types:
                current_template_id = st.session_state.document_type_to_template.get(doc_type)
                selected_index = 0
                for i, (template_id, _) in enumerate(template_options):
                    if template_id == current_template_id:
                        selected_index = i
                        break
                selected_template_name_dt = st.selectbox(f'Template for {doc_type}', options=[option[1] for option in template_options], index=selected_index, key=f"template_{doc_type.replace(' ', '_').lower()}", help=f'Select a metadata template for {doc_type} documents')
                selected_template_id_dt = ''
                for template_id, template_name in template_options:
                    if template_name == selected_template_name_dt:
                        selected_template_id_dt = template_id
                        break
                st.session_state.document_type_to_template[doc_type] = selected_template_id_dt
        current_general_template_id = st.session_state.metadata_config.get('template_id', '')
        general_selected_index = 0
        for i, (id_val, _) in enumerate(template_options):
            if id_val == current_general_template_id:
                general_selected_index = i
                break
        selected_template_name = st.selectbox('Select a metadata template (for all files if not mapped by type)', options=[option[1] for option in template_options], index=general_selected_index, key='template_selectbox', help='Select a metadata template to use for structured extraction. This is a fallback if no type-specific template is mapped.')
        selected_template_id = ''
        for template_id, template_name in template_options:
            if template_name == selected_template_name:
                selected_template_id = template_id
                break
        st.session_state.metadata_config['template_id'] = selected_template_id
        st.session_state.metadata_config['use_template'] = selected_template_id != ''
        if selected_template_id:
            template = templates[selected_template_id]
            st.write('#### Template Details')
            st.write(f"**Name:** {template['displayName']}")
            st.write(f"**ID:** {template['id']}")
            st.write('**Fields:**')
            for field in template['fields']:
                st.write(f"- {field['displayName']} ({field['type']})")
        else:
            st.write('#### Custom Fields')
            st.write('Define custom fields for structured extraction')
            if 'custom_fields' not in st.session_state.metadata_config:
                st.session_state.metadata_config['custom_fields'] = []
            for i, field in enumerate(st.session_state.metadata_config['custom_fields']):
                col1, col2, col3 = st.columns([3, 2, 1])
                with col1:
                    field_name = st.text_input('Field Name', value=field['name'], key=f'field_name_{i}', help='Name of the custom field')
                with col2:
                    field_type = st.selectbox('Field Type', options=['string', 'number', 'date', 'enum'], index=['string', 'number', 'date', 'enum'].index(field['type']), key=f'field_type_{i}', help='Type of the custom field')
                with col3:
                    if st.button('Remove', key=f'remove_field_{i}'):
                        st.session_state.metadata_config['custom_fields'].pop(i)
                        st.rerun()
                st.session_state.metadata_config['custom_fields'][i]['name'] = field_name
                st.session_state.metadata_config['custom_fields'][i]['type'] = field_type
            if st.button('Add Field', key='add_field_button'):
                st.session_state.metadata_config['custom_fields'].append({'name': f"Field {len(st.session_state.metadata_config['custom_fields']) + 1}", 'type': 'string'})
                st.rerun()
    st.subheader('AI Model Selection')
    all_models_with_desc = {'google__gemini_2_0_flash_lite_preview': 'Google Gemini 2.0 Flash Lite: Lightweight multimodal model (Default for Box AI Extract) (Preview)', 'azure__openai__gpt_4o_mini': 'Azure OpenAI GPT-4o Mini: Lightweight multimodal model', 'azure__openai__gpt_4_1_mini': 'Azure OpenAI GPT-4.1 Mini: Lightweight multimodal model (Default for some Box AI features)', 'azure__openai__gpt_4_1': 'Azure OpenAI GPT-4.1: Highly efficient multimodal model for complex tasks', 'google__gemini_2_0_flash_001': 'Google Gemini 2.0 Flash: Optimal for high-volume, high-frequency tasks', 'google__gemini_1_5_flash_001': 'Google Gemini 1.5 Flash: High volume tasks & latency-sensitive applications', 'google__gemini_1_5_pro_001': 'Google Gemini 1.5 Pro: Foundation model for various multimodal tasks', 'aws__claude_3_haiku': 'AWS Claude 3 Haiku: Tailored for various language tasks', 'aws__claude_3_sonnet': 'AWS Claude 3 Sonnet: Advanced language tasks, comprehension & context handling', 'aws__claude_3_5_sonnet': 'AWS Claude 3.5 Sonnet: Enhanced language understanding and generation', 'aws__claude_3_7_sonnet': 'AWS Claude 3.7 Sonnet: Enhanced language understanding and generation', 'aws__titan_text_lite': 'AWS Titan Text Lite: Advanced language processing, extensive contexts', 'ibm__llama_3_2_90b_vision_instruct': 'IBM Llama 3.2 90B Vision Instruct: Instruction-tuned vision model', 'ibm__llama_4_scout': 'IBM Llama 4 Scout: Natively multimodal model for text and multimodal experiences'}
    allowed_model_names = list(all_models_with_desc.keys())
    model_display_names = [all_models_with_desc[name] for name in allowed_model_names]
    current_model = st.session_state.metadata_config.get('ai_model', 'google__gemini_2_0_flash_lite_preview')
    try:
        current_model_index = allowed_model_names.index(current_model)
    except ValueError:
        current_model_index = 0
        st.session_state.metadata_config['ai_model'] = allowed_model_names[0]
    selected_model_display_name = st.selectbox('Select AI Model', options=model_display_names, index=current_model_index, key='ai_model_selectbox', help='Choose the AI model for metadata extraction. Availability may vary.')
    selected_model_name = allowed_model_names[model_display_names.index(selected_model_display_name)]
    st.session_state.metadata_config['ai_model'] = selected_model_name
    st.subheader('Batch Processing Configuration')
    batch_size = st.number_input('Batch Size for Processing', min_value=1, max_value=100, value=st.session_state.metadata_config.get('batch_size', 5), step=1, key='batch_size_number_input', help='Number of files to process in each batch. Adjust based on API limits and performance.')
    st.session_state.metadata_config['batch_size'] = batch_size
    st.markdown('--- ')
    if st.button('Save Configuration and Proceed to Process Files', key='save_config_button', use_container_width=True):
        st.session_state.current_page = 'Process Files'
        st.rerun()