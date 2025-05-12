import streamlit as st
import logging
import json
import os
from typing import Dict, Any, List, Optional
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_enhanced_processing():
    """
    Test the enhanced processing functionality
    """
    print('Testing enhanced processing functionality...')
    if not hasattr(st.session_state, 'metadata_config'):
        st.session_state.metadata_config = {'extraction_method': 'freeform', 'freeform_prompt': 'Extract key metadata from this document including dates, names, amounts, and other important information.', 'use_template': False, 'template_id': '', 'custom_fields': [], 'ai_model': 'google__gemini_2_0_flash_001', 'batch_size': 5, 'document_type_prompts': {}}
    if not hasattr(st.session_state, 'document_categorization'):
        st.session_state.document_categorization = {'is_categorized': True, 'results': {'file1': {'document_type': 'Financial Report'}, 'file2': {'document_type': 'Invoices'}, 'file3': {'document_type': 'Tax'}}}
    if not hasattr(st.session_state, 'document_type_to_template'):
        st.session_state.document_type_to_template = {'Financial Report': 'enterprise_123456_financialReport', 'Invoices': 'enterprise_123456_invoice', 'Tax': 'enterprise_123456_tax'}
    from modules.enhanced_processing import get_document_type_for_file, process_file
    print('\nTesting document type specific prompts...')
    st.session_state.metadata_config['document_type_prompts'] = {'Financial Report': 'Extract financial data including revenue, profit, and fiscal year.', 'Invoices': 'Extract invoice details including invoice number, date, amount, and vendor.', 'Tax': 'Extract tax information including tax year, filing status, and tax amount.'}
    file_id = 'file1'
    document_type = get_document_type_for_file(file_id)
    print(f'Document type for file1: {document_type}')
    if document_type == 'Financial Report':
        print('✅ Successfully retrieved document type')
    else:
        print('❌ Failed to retrieve document type')

    def mock_extract_freeform_metadata(file_id, prompt, ai_model):
        print(f'Mock extraction for file {file_id} with prompt: {prompt[:50]}...')
        return {'answer': {'extracted': 'data', 'prompt_used': prompt}}

    def mock_extract_structured_metadata(file_id, metadata_template=None, fields=None, ai_model=None):
        if metadata_template:
            print(f'Mock structured extraction for file {file_id} with template: {metadata_template}')
            return {'answer': {'extracted': 'data', 'template_used': metadata_template}}
        elif fields:
            print(f'Mock structured extraction for file {file_id} with fields: {fields}')
            return {'answer': {'extracted': 'data', 'fields_used': fields}}
        return {'error': 'No template or fields provided'}
    extraction_functions = {'extract_freeform_metadata': mock_extract_freeform_metadata, 'extract_structured_metadata': mock_extract_structured_metadata}
    print('\nTesting freeform extraction with document type specific prompt...')
    st.session_state.metadata_config['extraction_method'] = 'freeform'
    file = {'id': 'file1', 'name': 'financial_report.pdf'}
    result = process_file(file, extraction_functions)
    if result['success'] and 'prompt_used' in result['data']:
        prompt_used = result['data']['prompt_used']
        expected_prompt = st.session_state.metadata_config['document_type_prompts']['Financial Report']
        if prompt_used == expected_prompt:
            print('✅ Successfully used document type specific prompt for Financial Report')
        else:
            print('❌ Failed to use document type specific prompt')
            print(f'Expected: {expected_prompt}')
            print(f'Got: {prompt_used}')
    else:
        print('❌ Failed to process file or retrieve prompt used')
    print('\nTesting structured extraction with document type specific template...')
    st.session_state.metadata_config['extraction_method'] = 'structured'
    st.session_state.metadata_config['use_template'] = True
    st.session_state.metadata_config['template_id'] = 'enterprise_123456_general'
    file = {'id': 'file1', 'name': 'financial_report.pdf'}
    result = process_file(file, extraction_functions)
    if result['success'] and 'template_used' in result['data']:
        template_used = result['data']['template_used']
        expected_template_key = 'financialReport'
        if expected_template_key in str(template_used):
            print('✅ Successfully used document type specific template for Financial Report')
        else:
            print('❌ Failed to use document type specific template')
            print(f'Expected template key: {expected_template_key}')
            print(f'Got: {template_used}')
    else:
        print('❌ Failed to process file or retrieve template used')
    print('\nTesting fallback to general template...')
    if 'Financial Report' in st.session_state.document_type_to_template:
        del st.session_state.document_type_to_template['Financial Report']
    file = {'id': 'file1', 'name': 'financial_report.pdf'}
    result = process_file(file, extraction_functions)
    if result['success'] and 'template_used' in result['data']:
        template_used = result['data']['template_used']
        general_template_key = 'general'
        if general_template_key in str(template_used) or 'enterprise_123456_general' in str(template_used):
            print('✅ Successfully fell back to general template when no document type specific template is available')
        else:
            print('❌ Failed to fall back to general template')
            print(f'Expected general template')
            print(f'Got: {template_used}')
    else:
        print('❌ Failed to process file or retrieve template used')
    print('\nTesting multiple files with different document types...')
    st.session_state.document_type_to_template['Financial Report'] = 'enterprise_123456_financialReport'
    files = [{'id': 'file1', 'name': 'financial_report.pdf'}, {'id': 'file2', 'name': 'invoice.pdf'}, {'id': 'file3', 'name': 'tax_document.pdf'}]
    results = {}
    for file in files:
        result = process_file(file, extraction_functions)
        results[file['id']] = result
    all_correct = True
    for file_id, result in results.items():
        if not result['success']:
            print(f'❌ Failed to process file {file_id}')
            all_correct = False
            continue
        document_type = get_document_type_for_file(file_id)
        if not document_type:
            print(f'❌ Failed to get document type for file {file_id}')
            all_correct = False
            continue
        if 'template_used' in result['data']:
            template_used = result['data']['template_used']
            expected_template = st.session_state.document_type_to_template.get(document_type)
            if expected_template and expected_template.split('_')[-1] in str(template_used):
                print(f'✅ File {file_id} ({document_type}) used correct template')
            else:
                print(f'❌ File {file_id} ({document_type}) used incorrect template')
                print(f'Expected: {expected_template}')
                print(f'Got: {template_used}')
                all_correct = False
    if all_correct:
        print('✅ Successfully processed multiple files with different document types')
    else:
        print('❌ Some files were not processed correctly')
    print('\nEnhanced processing test completed.')
    return {'success': True, 'results': results}
if __name__ == '__main__':
    test_results = test_enhanced_processing()
    print(f'\nTest results: {test_results}')