import streamlit as st

# --- Page Config --- 
# Must be the first Streamlit command
st.set_page_config(layout="wide") 

import os
import sys
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path

# Configure logging
# Corrected format string with standard single quotes
logging.basicConfig(level=logging.INFO, 
                   format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Add the parent directory to sys.path
sys.path.append(str(Path(__file__).parent.parent))

# Import modules
from modules.authentication import authenticate
from modules.file_browser import file_browser
from modules.metadata_config import metadata_config
from modules.processing import process_files
from modules.results_viewer import view_results
from modules.direct_metadata_application_v3_fixed import apply_metadata_direct as apply_metadata
from modules.document_categorization import document_categorization
from modules.metadata_template_retrieval import get_metadata_templates, initialize_template_state
# Import the modified horizontal workflow component (now visual only)
from modules.horizontal_workflow import display_horizontal_workflow
# Optionally re-add user journey guide if needed later
# from modules.user_journey_guide import user_journey_guide, display_step_help 


# Session timeout configuration
SESSION_TIMEOUT_MINUTES = 60  # Increased from default

# Centralized session state initialization
def initialize_session_state():
    """
    Initialize all session state variables in a centralized function
    to ensure consistency across the application
    """
    # Core session state variables
    if not hasattr(st.session_state, "authenticated"):
        st.session_state.authenticated = False
        logger.info("Initialized authenticated in session state")
    
    if not hasattr(st.session_state, "client"):
        st.session_state.client = None
        logger.info("Initialized client in session state")
    
    if not hasattr(st.session_state, "current_page"):
        st.session_state.current_page = "Home"
        logger.info("Initialized current_page in session state")
    
    # Session management
    if not hasattr(st.session_state, "last_activity"):
        st.session_state.last_activity = datetime.now()
        logger.info("Initialized last_activity in session state")
    
    # File selection and processing variables
    if not hasattr(st.session_state, "selected_files"):
        st.session_state.selected_files = []
        logger.info("Initialized selected_files in session state")
    
    # Folder selection
    if not hasattr(st.session_state, "selected_folders"):
        st.session_state.selected_folders = []
        logger.info("Initialized selected_folders in session state")
    
    # Metadata configuration
    if not hasattr(st.session_state, "metadata_config"):
        st.session_state.metadata_config = {
            "extraction_method": "freeform",
            "freeform_prompt": "Extract key metadata from this document including dates, names, amounts, and other important information.",
            "use_template": False,
            "template_id": "",
            "custom_fields": [],
            "ai_model": "google__gemini_2_0_flash_001",
            "batch_size": 5
        }
        logger.info("Initialized metadata_config in session state")
    
    # Extraction results
    if not hasattr(st.session_state, "extraction_results"):
        st.session_state.extraction_results = {}
        logger.info("Initialized extraction_results in session state")
    
    # Selected results for metadata application - FIXED: Use direct attribute assignment
    if not hasattr(st.session_state, "selected_result_ids"):
        st.session_state.selected_result_ids = []
        logger.info("Initialized selected_result_ids in session state")
    
    # Application state for metadata application
    if not hasattr(st.session_state, "application_state"):
        st.session_state.application_state = {
            "is_applying": False,
            "applied_files": 0,
            "total_files": 0,
            "current_batch": [],
            "results": {},
            "errors": {}
        }
        logger.info("Initialized application_state in session state")
    
    # Processing state for file processing
    if not hasattr(st.session_state, "processing_state"):
        st.session_state.processing_state = {
            "is_processing": False,
            "processed_files": 0,
            "total_files": 0,
            "current_file_index": -1,
            "current_file": "",
            "results": {},
            "errors": {},
            "retries": {},
            "max_retries": 3,
            "retry_delay": 2,
            "visualization_data": {}
        }
        logger.info("Initialized processing_state in session state")
    
    # Debug information
    if not hasattr(st.session_state, "debug_info"):
        st.session_state.debug_info = []
        logger.info("Initialized debug_info in session state")
    
    # Metadata templates
    if not hasattr(st.session_state, "metadata_templates"):
        st.session_state.metadata_templates = {}
        logger.info("Initialized metadata_templates in session state")
    
    # Feedback data
    if not hasattr(st.session_state, "feedback_data"):
        st.session_state.feedback_data = {}
        logger.info("Initialized feedback_data in session state")
    
    # Initialize document categorization state
    if not hasattr(st.session_state, "document_categorization"):
        st.session_state.document_categorization = {
            "is_categorized": False,
            "categorized_files": 0,
            "total_files": 0,
            "results": {},  # file_id -> categorization result
            "errors": {},   # file_id -> error message
            "processing_state": {
                "is_processing": False,
                "current_file_index": -1,
                "current_file": "",
                "current_batch": [],
                "batch_size": 5
            }
        }
        logger.info("Initialized document_categorization in session state")
    
    # Initialize template state
    initialize_template_state()
    
    # UI preferences (Keep for potential future use, remove journey/help toggles for now)
    if not hasattr(st.session_state, "ui_preferences"):
        st.session_state.ui_preferences = {
            # "show_user_journey": True, # Removed for now
            # "show_step_help": True, # Removed for now
            "dark_mode": False,
            "compact_view": False
        }
        logger.info("Initialized ui_preferences in session state")

# Initialize session state
initialize_session_state()

# Update last activity timestamp
def update_activity():
    st.session_state.last_activity = datetime.now()

# Check if session has timed out
def check_session_timeout():
    if not hasattr(st.session_state, "last_activity"):
        update_activity()
        return False
    
    time_since_last_activity = datetime.now() - st.session_state.last_activity
    if time_since_last_activity > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
        logger.info(f"Session timed out after {time_since_last_activity}")
        return True
    
    return False

# Navigation function (used by sidebar buttons)
def navigate_to(page):
    st.session_state.current_page = page
    update_activity()
    logger.info(f"Navigated to page: {page}")
    # No st.rerun() here, it happens implicitly after button click or handled by caller

# --- Sidebar --- 
with st.sidebar:
    st.title("Box AI Metadata")
    
    if hasattr(st.session_state, "authenticated") and st.session_state.authenticated:
        # Session timeout check
        if check_session_timeout():
            st.warning("Your session has timed out due to inactivity. Please log in again.")
            st.session_state.authenticated = False
            st.session_state.client = None
            # Use callback for navigation on timeout to ensure rerun
            st.button("Login Again", on_click=navigate_to, args=("Home",), key="timeout_login_btn")
            st.rerun() # Force stop rendering the rest of the page
        else:
            update_activity()
        
        # Display session timeout info
        remaining_time = SESSION_TIMEOUT_MINUTES - (datetime.now() - st.session_state.last_activity).total_seconds() / 60
        st.caption(f"Session timeout: {int(remaining_time)} minutes remaining")
        
        # --- RESTORED Sidebar Navigation --- 
        st.subheader("Workflow Steps")
        if st.button("Home", use_container_width=True, key="nav_home"):
            navigate_to("Home")
            st.rerun() # Rerun after navigation
        
        if st.button("Select Files", use_container_width=True, key="nav_file_browser"):
            navigate_to("File Browser")
            st.rerun()
        
        if st.button("Categorize Documents", use_container_width=True, key="nav_doc_cat"):
            navigate_to("Document Categorization")
            st.rerun()
            
        if st.button("Configure Metadata", use_container_width=True, key="nav_meta_config"):
            navigate_to("Metadata Configuration")
            st.rerun()
            
        if st.button("Process Files", use_container_width=True, key="nav_process"):
            navigate_to("Process Files")
            st.rerun()
            
        if st.button("Review Results", use_container_width=True, key="nav_view"):
            navigate_to("View Results")
            st.rerun()
            
        if st.button("Apply Metadata", use_container_width=True, key="nav_apply"):
            navigate_to("Apply Metadata")
            st.rerun()
        # --- End Restored Navigation --- 
        
        st.markdown("--- ") # Separator
        
        # Keep Metadata Templates section
        st.subheader("Metadata Templates")
        template_count = len(st.session_state.metadata_templates) if hasattr(st.session_state, "metadata_templates") else 0
        st.write(f"{template_count} templates loaded")
        if hasattr(st.session_state, "template_cache_timestamp") and st.session_state.template_cache_timestamp:
            cache_time = datetime.fromtimestamp(st.session_state.template_cache_timestamp)
            st.write(f"Last updated: {cache_time.strftime('%Y-%m-%d %H:%M:%S')}") # Corrected format string quotes
        if st.button("Refresh Templates", key="refresh_templates_btn"):
            with st.spinner("Refreshing metadata templates..."):
                templates = get_metadata_templates(st.session_state.client, force_refresh=True)
                st.session_state.template_cache_timestamp = time.time()
                st.success(f"Retrieved {len(templates)} metadata templates")
                st.rerun()
        
        st.markdown("--- ") # Separator
        
        # Keep UI Settings (without journey/help toggles for now)
        with st.expander("UI Settings", expanded=False):
            # Removed checkboxes for show_user_journey and show_step_help
            st.session_state.ui_preferences["compact_view"] = st.checkbox(
                "Compact View", 
                value=st.session_state.ui_preferences.get("compact_view", False),
                key="compact_view_checkbox"
            )
        
        st.markdown("--- ") # Separator
        
        # Keep Logout button
        if st.button("Logout", use_container_width=True, key="nav_logout"):
            st.session_state.authenticated = False
            st.session_state.client = None
            navigate_to("Home") # Use navigate_to to reset page
            st.rerun()
    
    # Keep About section
    st.subheader("About")
    st.info(
        "This app connects to Box.com and uses Box AI API "
        "to extract metadata from files and apply it at scale."
    )

# --- Main Content Area --- 

if not hasattr(st.session_state, "authenticated") or not st.session_state.authenticated:
    # Authentication page (no workflow indicator needed here)
    st.title("Box AI Metadata Extraction - Login")
    authenticate()
else:
    # --- Display Horizontal Workflow (Visual Only) --- 
    # Call the modified workflow display function at the top
    display_horizontal_workflow(st.session_state.current_page)
    st.markdown("--- ") # Add a separator
    
    # Update activity timestamp (already done by navigate_to or check_session_timeout)
    # update_activity() # Redundant here
    
    # Retrieve metadata templates if needed (no change here)
    if st.session_state.authenticated and st.session_state.client:
        if not st.session_state.metadata_templates:
            with st.spinner("Retrieving metadata templates..."):
                templates = get_metadata_templates(st.session_state.client)
                st.session_state.template_cache_timestamp = time.time()
                logger.info(f"Retrieved {len(templates)} metadata templates")
    
    # Removed old step help display
    # if st.session_state.ui_preferences.get("show_step_help", True):
    #     display_step_help(st.session_state.current_page)
    
    # --- Display Current Page Content --- 
    # Use existing logic to render the content for the current page
    if not hasattr(st.session_state, "current_page") or st.session_state.current_page == "Home":
        # Home page content (Simplified welcome message)
        st.title("Box AI Metadata Extraction - Welcome")
        st.write("""
        Welcome! Use the workflow steps in the sidebar to navigate the application.
        The visual guide above shows your current progress.
        
        Select files, categorize them, configure metadata extraction, process, review, and apply.
        """)
        # Removed old welcome page workflow list and quick actions
        
    elif st.session_state.current_page == "File Browser":
        st.title("Step 2: Select Files") # Updated title for consistency
        file_browser()
    
    elif st.session_state.current_page == "Document Categorization":
        st.title("Step 3: Categorize Documents") # Updated title
        document_categorization()
    
    elif st.session_state.current_page == "Metadata Configuration":
        st.title("Step 4: Configure Metadata") # Updated title
        metadata_config()
    
    elif st.session_state.current_page == "Process Files":
        st.title("Step 5: Process Files")
        process_files()
    
    elif st.session_state.current_page == "View Results":
        st.title("Step 6: Review Results")
        view_results()
    
    elif st.session_state.current_page == "Apply Metadata":
        st.title("Step 7: Apply Metadata")
        apply_metadata()
        
    else:
        # Fallback if page is unknown
        st.error(f"Unknown page: {st.session_state.current_page}")
        st.button("Go to Login", on_click=navigate_to, args=("Home",))


