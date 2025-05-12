"""
Test script for the enhanced Box AI Metadata structured metadata application fix.

This script simulates the metadata application process with test data to verify
that the fix correctly handles structured metadata.
"""
import json
import logging
import sys
import os
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
sys.path.append('/home/ubuntu/Metadata-Extract-4.2-fixed-enhanced-v2')
from modules.direct_metadata_application_enhanced_fixed import fix_metadata_format, flatten_metadata_for_template

def test_metadata_transformation():
    """Test the metadata transformation process with real data from logs"""
    test_case_1 = {'answer': "{'identifier': 'AOFM 2023-24 Annual Report', 'title': 'Annual Report 2023-24', 'entityName': 'AUSTRALIAN OFFICE OF FINANCIAL MANAGEMENT', 'reportingPeriod': 'year ended 30 June 2024', 'dateOfPublication': '2024-09-11T00:00:00Z', 'value': 906.9, 'keywords': 'Australian Office of Financial Management, AOFM, debt financing, cash portfolio, investment programs', 'accessRestrictions': 'External'}", 'ai_agent_info': "{'processor': 'long_text', 'models': [{'name': 'google__text_embedding_005', 'provider': 'google', 'supported_purpose': 'embedding'}, {'name': 'google__gemini_2_0_flash_001', 'provider': 'google'}]}", 'created_at': '2025-04-21T01:45:58.091-07:00', 'completion_reason': 'done'}
    test_case_2 = {'answer': "{'identifier': 'Netflix-10-K-01272025.pdf', 'title': 'Annual Report on Form 10-K', 'entityName': 'Netflix, Inc.', 'reportingPeriod': 'fiscal year ended December 31, 2024', 'dateOfPublication': '2025-01-27T00:00:00Z', 'value': 39000966, 'keywords': 'entertainment, video, streaming, content, membership, growth, financial performance, intellectual property, competition, advertising', 'accessRestrictions': 'External'}", 'ai_agent_info': "{'processor': 'long_text', 'models': [{'name': 'google__text_embedding_005', 'provider': 'google'}, {'name': 'google__gemini_2_0_flash_001', 'provider': 'google'}]}", 'created_at': '2025-04-21T02:00:01.195-07:00', 'completion_reason': 'done'}
    test_case_3 = {'answer': "{'identifier': 'redr-australia-annual-report-fy24.pdf', 'title': 'Annual Report FY24', 'entityName': 'RedR Australia', 'reportingPeriod': 'FY24', 'dateOfPublication': '2024-06-30T00:00:00Z', 'value': 126, 'keywords': 'humanitarian, disaster response, training, experts, deployment, roster, partnerships, learning, financial reporting', 'accessRestrictions': 'External'}", 'ai_agent_info': "{'processor': 'basic_text', 'models': [{'name': 'google__gemini_2_0_flash_001', 'provider': 'google'}]}", 'created_at': '2025-04-21T02:00:05.165-07:00', 'completion_reason': 'done'}
    test_cases = [('AOFM 2023-24 Annual Report', test_case_1), ('Netflix-10-K-01272025.pdf', test_case_2), ('redr-australia-annual-report-fy24.pdf', test_case_3)]
    print('=' * 80)
    print('TESTING METADATA TRANSFORMATION PROCESS')
    print('=' * 80)
    for name, test_case in test_cases:
        print(f'\nTesting with {name}:')
        print('-' * 50)
        print('Original metadata:')
        print(json.dumps(test_case, indent=2))
        formatted_metadata = fix_metadata_format(test_case)
        print('\nAfter fix_metadata_format:')
        print(json.dumps(formatted_metadata, indent=2))
        flattened_metadata = flatten_metadata_for_template(formatted_metadata)
        print('\nAfter flatten_metadata_for_template (FINAL RESULT):')
        print(json.dumps(flattened_metadata, indent=2))
        print('\nValidation:')
        if 'answer' not in flattened_metadata and 'ai_agent_info' not in flattened_metadata:
            print('✅ Nested objects removed correctly')
        else:
            print('❌ Nested objects still present')
        if 'identifier' in flattened_metadata and 'title' in flattened_metadata:
            print('✅ Fields extracted to top level correctly')
        else:
            print('❌ Fields not extracted to top level')
        if isinstance(flattened_metadata.get('value'), (int, float, str)):
            print('✅ Value field has correct type')
        else:
            print('❌ Value field has incorrect type')
        print('-' * 50)
    print('\n' + '=' * 80)
    print('TEST COMPLETE')
    print('=' * 80)

def simulate_box_api_call(metadata):
    """Simulate a Box API call to verify the metadata structure"""
    required_fields = ['identifier', 'title', 'entityName', 'reportingPeriod']
    missing_fields = [field for field in required_fields if field not in metadata]
    if missing_fields:
        raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
    for key, value in metadata.items():
        if isinstance(value, dict):
            raise ValueError(f"Nested object found for key '{key}'. Box API expects flat structure.")
    return {'status': 'success', 'message': 'Metadata structure is valid for Box API', 'metadata': metadata}

def test_box_api_simulation():
    """Test the metadata with a simulated Box API call"""
    test_case = {'answer': "{'identifier': 'AOFM 2023-24 Annual Report', 'title': 'Annual Report 2023-24', 'entityName': 'AUSTRALIAN OFFICE OF FINANCIAL MANAGEMENT', 'reportingPeriod': 'year ended 30 June 2024', 'dateOfPublication': '2024-09-11T00:00:00Z', 'value': 906.9, 'keywords': 'Australian Office of Financial Management, AOFM, debt financing, cash portfolio, investment programs', 'accessRestrictions': 'External'}", 'ai_agent_info': "{'processor': 'long_text', 'models': [{'name': 'google__text_embedding_005', 'provider': 'google', 'supported_purpose': 'embedding'}, {'name': 'google__gemini_2_0_flash_001', 'provider': 'google'}]}", 'created_at': '2025-04-21T01:45:58.091-07:00', 'completion_reason': 'done'}
    print('\n' + '=' * 80)
    print('TESTING BOX API SIMULATION')
    print('=' * 80)
    print('\nTesting with original metadata (should fail):')
    try:
        result = simulate_box_api_call(test_case)
        print('❌ Test failed: Original metadata was accepted but should have been rejected')
    except ValueError as e:
        print(f'✅ Test passed: Original metadata correctly rejected with error: {str(e)}')
    formatted_metadata = fix_metadata_format(test_case)
    flattened_metadata = flatten_metadata_for_template(formatted_metadata)
    print('\nTesting with fixed metadata (should pass):')
    try:
        result = simulate_box_api_call(flattened_metadata)
        print(f"✅ Test passed: {result['message']}")
        print('Fixed metadata structure is valid for Box API')
    except ValueError as e:
        print(f'❌ Test failed: Fixed metadata was rejected with error: {str(e)}')
    print('\n' + '=' * 80)
    print('SIMULATION TEST COMPLETE')
    print('=' * 80)
if __name__ == '__main__':
    test_metadata_transformation()
    test_box_api_simulation()