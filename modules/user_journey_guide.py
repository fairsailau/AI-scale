import streamlit as st
from typing import List, Dict, Any, Optional

def user_journey_guide(current_page: str=None):
    """
    Display a user journey guide that explains the workflow steps
    
    Args:
        current_page: The current page being displayed
    """
    workflow_steps = [{'id': 'authentication', 'title': 'Authentication', 'description': 'Log in to your Box account to access your files.', 'page': 'Home', 'icon': '🔑'}, {'id': 'file_browser', 'title': 'File Selection', 'description': 'Browse your Box files and select individual files or entire folders for processing.', 'page': 'File Browser', 'icon': '📁'}, {'id': 'document_categorization', 'title': 'Document Categorization', 'description': 'Categorize your documents using Box AI to identify document types.', 'page': 'Document Categorization', 'icon': '🏷️'}, {'id': 'metadata_config', 'title': 'Metadata Configuration', 'description': 'Configure how metadata will be extracted from your files.', 'page': 'Metadata Configuration', 'icon': '⚙️'}, {'id': 'process_files', 'title': 'Process Files', 'description': 'Extract metadata from your files using Box AI.', 'page': 'Process Files', 'icon': '🔄'}, {'id': 'view_results', 'title': 'Review Results', 'description': 'Review the extracted metadata and make any necessary adjustments.', 'page': 'View Results', 'icon': '👁️'}, {'id': 'apply_metadata', 'title': 'Apply Metadata', 'description': 'Apply the extracted metadata to your Box files.', 'page': 'Apply Metadata', 'icon': '✅'}]
    current_step_index = 0
    if current_page:
        for i, step in enumerate(workflow_steps):
            if step['page'] == current_page:
                current_step_index = i
                break
    with st.sidebar.expander('📋 User Journey Guide', expanded=True):
        st.write('### Application Workflow')
        st.write('Follow these steps to extract and apply metadata to your Box files:')
        for i, step in enumerate(workflow_steps):
            if i < current_step_index:
                status = 'completed'
                prefix = '✅ '
            elif i == current_step_index:
                status = 'current'
                prefix = '🔶 '
            else:
                status = 'upcoming'
                prefix = '⬜ '
            step_container = st.container()
            with step_container:
                st.markdown(f"**{prefix} {i + 1}. {step['icon']} {step['title']}**", unsafe_allow_html=True)
                if status in ['current', 'completed']:
                    st.markdown(f"<div style='margin-left: 25px; font-size: 0.9em;'>{step['description']}</div>", unsafe_allow_html=True)
                if status == 'current':
                    st.markdown("<div style='margin-bottom: 15px;'></div>", unsafe_allow_html=True)
                if i < len(workflow_steps) - 1:
                    st.markdown("<hr style='margin: 5px 0; border: none; border-top: 1px solid rgba(0,0,0,0.1);'>", unsafe_allow_html=True)
        st.markdown('---')
        st.markdown("<div style='font-size: 0.8em;'>💡 <i>The current step is highlighted in orange. Completed steps are marked with a green checkmark.</i></div>", unsafe_allow_html=True)

def get_step_help_text(current_page: str) -> Optional[Dict[str, Any]]:
    """
    Get contextual help text for the current step
    
    Args:
        current_page: The current page being displayed
        
    Returns:
        dict: Help text information for the current step, or None if not available
    """
    help_texts = {'Home': {'title': 'Authentication', 'content': ['Enter your Box API credentials to authenticate with Box.', "You'll need a Client ID and Client Secret from your Box Developer Console.", "After authentication, you'll be able to access your Box files and folders."], 'tips': ['Make sure you have the correct permissions to access Box content.', 'Your credentials are only used for this session and are not stored permanently.']}, 'File Browser': {'title': 'File Selection', 'content': ['Browse through your Box folders to locate files for processing.', 'You can select individual files by checking the box next to each file.', 'To select an entire folder, click the folder checkbox to include all files within it.', 'Use the search and filter options to quickly find specific files.'], 'tips': ['You can process up to 100 files at once with batch processing.', 'For best results, group similar document types together.']}, 'Document Categorization': {'title': 'Document Categorization', 'content': ['This step uses Box AI to automatically categorize your documents.', 'Documents will be classified into types such as Invoices, Contracts, Policies, etc.', 'You can adjust batch size to process multiple files simultaneously.', 'Results include document type, confidence score, and reasoning.'], 'tips': ['Higher batch sizes process faster but may hit API rate limits.', 'You can filter and sort results after categorization is complete.']}, 'Metadata Configuration': {'title': 'Metadata Configuration', 'content': ['Configure how metadata will be extracted from your files.', 'Choose between freeform extraction or structured extraction using templates.', 'Select the AI model to use for extraction.', 'Configure batch processing settings for optimal performance.'], 'tips': ['Freeform extraction works well for varied document types.', 'Templates provide more consistent results for specific document types.']}, 'Process Files': {'title': 'Process Files', 'content': ['This step extracts metadata from your selected files using Box AI.', 'Files are processed in batches according to your configuration.', 'Progress is tracked in real-time with detailed status updates.', 'Results are stored for review in the next step.'], 'tips': ['Processing large files may take longer.', 'You can cancel processing at any time and resume later.']}, 'View Results': {'title': 'Review Results', 'content': ['Review the metadata extracted from your files.', 'You can edit metadata values if needed.', 'Select which files to apply metadata to in the next step.', 'Filter and sort results to quickly find specific items.'], 'tips': ['Check confidence scores to identify potential issues.', 'You can download results as CSV for offline analysis.']}, 'Apply Metadata': {'title': 'Apply Metadata', 'content': ['Apply the extracted metadata to your Box files.', 'Metadata is applied as properties that can be searched and filtered in Box.', 'You can normalize keys and filter placeholder values.', 'Progress is tracked in real-time with detailed status updates.'], 'tips': ['Applying metadata to many files may take some time.', 'You can verify applied metadata in Box after completion.']}}
    return help_texts.get(current_page)

def display_step_help(current_page: str):
    """
    Display contextual help for the current step
    
    Args:
        current_page: The current page being displayed
    """
    help_info = get_step_help_text(current_page)
    if help_info:
        with st.expander(f"ℹ️ Help: {help_info['title']}", expanded=False):
            for item in help_info['content']:
                st.write(f'• {item}')
            if 'tips' in help_info and help_info['tips']:
                st.write('---')
                st.write('**💡 Tips:**')
                for tip in help_info['tips']:
                    st.write(f'• {tip}')