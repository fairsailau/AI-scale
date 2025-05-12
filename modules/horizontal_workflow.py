import streamlit as st
import logging
logger = logging.getLogger(__name__)
workflow_steps = [{'id': 'authentication', 'title': 'Login', 'page': 'Home', 'icon': '🔑'}, {'id': 'file_browser', 'title': 'Select Files', 'page': 'File Browser', 'icon': '📁'}, {'id': 'document_categorization', 'title': 'Categorize', 'page': 'Document Categorization', 'icon': '🏷️'}, {'id': 'metadata_config', 'title': 'Configure', 'page': 'Metadata Configuration', 'icon': '⚙️'}, {'id': 'process_files', 'title': 'Process', 'page': 'Process Files', 'icon': '🔄'}, {'id': 'view_results', 'title': 'Review', 'page': 'View Results', 'icon': '👁️'}, {'id': 'apply_metadata', 'title': 'Apply', 'page': 'Apply Metadata', 'icon': '✅'}]

def display_horizontal_workflow(current_page_id: str):
    """
    Displays the horizontal workflow indicator using Salesforce-style chevrons.
    This version is purely visual and does not handle clicks.

    Args:
        current_page_id: The page ID of the current step (e.g., "Home", "File Browser").
    """
    current_step_index = -1
    for i, step in enumerate(workflow_steps):
        if step['page'] == current_page_id:
            current_step_index = i
            break
    css = '\n    <style>\n        .chevron-container {\n            display: flex;\n            justify-content: center; /* Center the chevrons */\n            list-style: none;\n            padding: 0;\n            margin: 20px 0; /* Add some margin */\n            width: 100%;\n            overflow-x: auto; /* Allow horizontal scrolling if needed */\n        }\n        .chevron-step {\n            background-color: #e9ecef; /* Default upcoming background */\n            color: #6c757d; /* Default upcoming text */\n            padding: 0.5rem 1rem 0.5rem 2rem; /* Adjust padding */\n            margin-right: -1rem; /* Overlap chevrons */\n            position: relative;\n            text-align: center;\n            min-width: 120px; /* Minimum width for each step */\n            white-space: nowrap;\n            border: 1px solid #ced4da;\n            cursor: default; /* Default cursor - not clickable */\n        }\n        .chevron-step::before, .chevron-step::after {\n            content: "";\n            position: absolute;\n            top: 0;\n            border: 0 solid transparent;\n            border-width: 1.55rem 1rem; /* Controls size/angle of arrow */\n            width: 0;\n            height: 0;\n        }\n        .chevron-step::before {\n            left: -0.05rem; /* Position left arrow */\n            border-left-color: white; /* Match page background */\n            border-left-width: 1rem;\n        }\n        .chevron-step::after {\n            left: 100%;\n            z-index: 2;\n            border-left-color: #e9ecef; /* Match step background */\n        }\n        /* First step doesn\'t need the left cutout */\n        .chevron-step:first-child {\n            padding-left: 1rem;\n            border-top-left-radius: 5px;\n            border-bottom-left-radius: 5px;\n        }\n        .chevron-step:first-child::before {\n            display: none;\n        }\n        /* Last step doesn\'t need the right arrow */\n        .chevron-step:last-child {\n            margin-right: 0;\n            padding-right: 1rem;\n            border-top-right-radius: 5px;\n            border-bottom-right-radius: 5px;\n        }\n        .chevron-step:last-child::after {\n            display: none;\n        }\n\n        /* Completed Step Styling */\n        .chevron-step-completed {\n            background-color: #cfe2ff; /* Light blue background */\n            color: #052c65; /* Dark blue text */\n            border-color: #9ec5fe;\n            /* cursor: pointer; Removed - not clickable */\n        }\n        .chevron-step-completed::after {\n            border-left-color: #cfe2ff; /* Match completed background */\n        }\n        /* Removed hover styles as it\'s not interactive */\n        /* .chevron-step-completed:hover { ... } */\n        /* .chevron-step-completed:hover::after { ... } */\n\n        /* Current Step Styling */\n        .chevron-step-current {\n            background-color: #0d6efd; /* Blue background */\n            color: white;\n            font-weight: bold;\n            z-index: 3; /* Ensure current step overlaps others */\n            border-color: #0a58ca;\n        }\n        .chevron-step-current::after {\n            border-left-color: #0d6efd; /* Match current background */\n        }\n        \n        /* Removed link styling as it\'s not interactive */\n        /* .chevron-step a { ... } */\n\n    </style>\n    '
    st.markdown(css, unsafe_allow_html=True)
    html_content = '<div class="chevron-container">'
    for i, step in enumerate(workflow_steps):
        status_class = ''
        if i < current_step_index:
            status_class = 'chevron-step-completed'
        elif i == current_step_index:
            status_class = 'chevron-step-current'
        else:
            status_class = 'chevron-step-upcoming'
        step_html = f'<div class="chevron-step {status_class}" '
        step_html += f''' title="{step['title']} (Step {i + 1})">'''
        step_html += f"{step['title']}"
        if i < current_step_index:
            step_html += ' ✓'
        step_html += '</div>'
        html_content += step_html
    html_content += '</div>'
    st.markdown(html_content, unsafe_allow_html=True)