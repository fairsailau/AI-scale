import streamlit as st
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def initialize_app_session_state():
    """
    Global session state initialization function to be called at the start of the application.
    This ensures all required session state variables are properly initialized.
    """
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        logger.info('Initialized authenticated in session state')
    if 'client' not in st.session_state:
        st.session_state.client = None
        logger.info('Initialized client in session state')
    if 'current_page' not in st.session_state:
        st.session_state.current_page = 'Home'
        logger.info('Initialized current_page in session state')
    if 'selected_files' not in st.session_state:
        st.session_state.selected_files = []
        logger.info('Initialized selected_files in session state')
    if 'metadata_config' not in st.session_state:
        st.session_state.metadata_config = {'extraction_method': 'freeform', 'freeform_prompt': 'Extract key metadata from this document.', 'use_template': False, 'template_id': '', 'custom_fields': [], 'ai_model': 'azure__openai__gpt_4o_mini', 'batch_size': 5}
        logger.info('Initialized metadata_config in session state')
    if 'extraction_results' not in st.session_state:
        st.session_state.extraction_results = {}
        logger.info('Initialized extraction_results in session state')
    if 'selected_result_ids' not in st.session_state:
        st.session_state.selected_result_ids = []
        logger.info('Initialized selected_result_ids in session state')
    if 'application_state' not in st.session_state:
        st.session_state.application_state = {'is_applying': False, 'applied_files': 0, 'total_files': 0, 'current_batch': [], 'results': {}, 'errors': {}}
        logger.info('Initialized application_state in session state')
    if 'processing_state' not in st.session_state:
        st.session_state.processing_state = {'is_processing': False, 'current_file_index': -1, 'total_files': 0, 'processed_files': 0, 'results': {}, 'errors': {}}
        logger.info('Initialized processing_state in session state')
    if 'debug_info' not in st.session_state:
        st.session_state.debug_info = {}
        logger.info('Initialized debug_info in session state')
    if 'metadata_templates' not in st.session_state:
        st.session_state.metadata_templates = []
        logger.info('Initialized metadata_templates in session state')
    if 'feedback_data' not in st.session_state:
        st.session_state.feedback_data = {}
        logger.info('Initialized feedback_data in session state')

def get_safe_session_state(key, default_value=None):
    """
    Safely get a value from session state with a fallback default value.
    This prevents KeyError when accessing session state variables.
    
    Args:
        key (str): The session state key to access
        default_value: The default value to return if key doesn't exist
        
    Returns:
        The value from session state or the default value
    """
    try:
        return st.session_state[key]
    except (KeyError, AttributeError):
        logger.warning(f"Session state key '{key}' not found, using default value")
        return default_value

def set_safe_session_state(key, value):
    """
    Safely set a value in session state.
    This ensures the session state is properly initialized before setting values.
    
    Args:
        key (str): The session state key to set
        value: The value to set
    """
    try:
        st.session_state[key] = value
        return True
    except Exception as e:
        logger.error(f"Error setting session state key '{key}': {str(e)}")
        return False

def reset_session_state():
    """
    Reset the session state to its initial values.
    This can be used as a recovery mechanism when errors occur.
    """
    keys_to_reset = ['extraction_results', 'selected_result_ids', 'application_state', 'processing_state']
    for key in keys_to_reset:
        if key in st.session_state:
            del st.session_state[key]
    initialize_app_session_state()
    logger.info('Session state has been reset')
    return True

def debug_session_state():
    """
    Create a debug view of the current session state.
    This can be used to diagnose session state issues.
    
    Returns:
        dict: A dictionary containing debug information about session state
    """
    debug_info = {'session_state_keys': list(st.session_state.keys()), 'has_extraction_results': 'extraction_results' in st.session_state, 'extraction_results_type': str(type(get_safe_session_state('extraction_results'))), 'extraction_results_keys': list(get_safe_session_state('extraction_results', {}).keys()), 'has_selected_files': 'selected_files' in st.session_state, 'selected_files_count': len(get_safe_session_state('selected_files', [])), 'has_processing_state': 'processing_state' in st.session_state, 'has_application_state': 'application_state' in st.session_state}
    logger.info(f'Session state debug info: {debug_info}')
    return debug_info