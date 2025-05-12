import streamlit as st
import logging
import json
import requests
import re
import os
import datetime
import pandas as pd
import altair as alt
from typing import Dict, Any, List, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Merged Functions and UI from document_categorization (2).py and (3).py ---

def document_categorization():
    """
    Enhanced document categorization with improved confidence metrics and user-defined types.
    (Merged from versions 2 and 3)
    """
    st.title("Document Categorization")
    
    if not st.session_state.authenticated or not st.session_state.client:
        st.error("Please authenticate with Box first")
        return
    
    if not st.session_state.selected_files:
        st.warning("No files selected. Please select files in the File Browser first.")
        if st.button("Go to File Browser", key="go_to_file_browser_button_cat"):
            st.session_state.current_page = "File Browser"
            st.rerun()
        return
    
    if "document_categorization" not in st.session_state:
        st.session_state.document_categorization = {
            "is_categorized": False,
            "results": {},
            "errors": {}
        }
    
    if "confidence_thresholds" not in st.session_state:
        st.session_state.confidence_thresholds = {
            "auto_accept": 0.85,
            "verification": 0.6,
            "rejection": 0.4
        }
        
    if "document_types" not in st.session_state or not isinstance(st.session_state.document_types, list) or \
       not all(isinstance(item, dict) and "name" in item and "description" in item for item in st.session_state.document_types):
        logger.warning("Initializing/Resetting document_types in session state to default structure.")
        st.session_state.document_types = [
            {"name": "Sales Contract", "description": "Contracts related to sales agreements and terms."},
            {"name": "Invoices", "description": "Billing documents issued by a seller to a buyer, indicating quantities, prices for products or services."},
            {"name": "Tax", "description": "Documents related to government taxation (e.g., tax forms, filings, receipts)."},
            {"name": "Financial Report", "description": "Reports detailing the financial status or performance of an entity (e.g., balance sheets, income statements)."},
            {"name": "Employment Contract", "description": "Agreements outlining terms and conditions of employment between an employer and employee."},
            {"name": "PII", "description": "Documents containing Personally Identifiable Information that needs careful handling."},
            {"name": "Other", "description": "Any document not fitting into the specific categories above."}
        ]
    
    num_files = len(st.session_state.selected_files)
    st.write(f"Ready to categorize {num_files} files using Box AI.")
    
    tab1, tab2 = st.tabs(["Categorization", "Settings"])
    
    with tab1:
        all_models_with_desc = {
            "azure__openai__gpt_4_1_mini": "Azure OpenAI GPT-4.1 Mini: Lightweight multimodal model (Default for Box AI for Docs/Notes Q&A)",
            "google__gemini_2_0_flash_lite_preview": "Google Gemini 2.0 Flash Lite: Lightweight multimodal model (Preview)",
            "azure__openai__gpt_4o_mini": "Azure OpenAI GPT-4o Mini: Lightweight multimodal model",
            "azure__openai__gpt_4o": "Azure OpenAI GPT-4o: Highly efficient multimodal model for complex tasks",
            "azure__openai__gpt_4_1": "Azure OpenAI GPT-4.1: Highly efficient multimodal model for complex tasks",
            "azure__openai__gpt_o3": "Azure OpenAI GPT o3: Highly efficient multimodal model for complex tasks",
            "azure__openai__gpt_o4-mini": "Azure OpenAI GPT o4-mini: Highly efficient multimodal model for complex tasks",
            "google__gemini_2_5_pro_preview": "Google Gemini 2.5 Pro: Optimal for high-volume, high-frequency tasks (Preview)",
            "google__gemini_2_5_flash_preview": "Google Gemini 2.5 Flash: Optimal for high-volume, high-frequency tasks (Preview)",
            "google__gemini_2_0_flash_001": "Google Gemini 2.0 Flash: Optimal for high-volume, high-frequency tasks",
            "google__gemini_1_5_flash_001": "Google Gemini 1.5 Flash: High volume tasks & latency-sensitive applications",
            "google__gemini_1_5_pro_001": "Google Gemini 1.5 Pro: Foundation model for various multimodal tasks",
            "aws__claude_3_haiku": "AWS Claude 3 Haiku: Tailored for various language tasks",
            "aws__claude_3_sonnet": "AWS Claude 3 Sonnet: Advanced language tasks, comprehension & context handling",
            "aws__claude_3_5_sonnet": "AWS Claude 3.5 Sonnet: Enhanced language understanding and generation",
            "aws__claude_3_7_sonnet": "AWS Claude 3.7 Sonnet: Enhanced language understanding and generation",
            "aws__titan_text_lite": "AWS Titan Text Lite: Advanced language processing, extensive contexts",
            "ibm__llama_3_2_instruct": "IBM Llama 3.2 Instruct: Instruction-tuned text model for dialogue, retrieval, summarization",
            "ibm__llama_3_2_90b_vision_instruct": "IBM Llama 3.2 90B Vision Instruct: Instruction-tuned vision model (From Error Log)",
            "ibm__llama_4_scout": "IBM Llama 4 Scout: Natively multimodal model for text and multimodal experiences",
            "xai__grok_3_beta": "xAI Grok 3: Excels at data extraction, coding, summarization (Beta)",
            "xai__grok_3_mini_beta": "xAI Grok 3 Mini: Lightweight model for logic-based tasks (Beta)"
        }
        allowed_model_names = [
            "azure__openai__gpt_4o_mini", "azure__openai__gpt_4_1", "azure__openai__gpt_4_1_mini",
            "google__gemini_1_5_pro_001", "google__gemini_1_5_flash_001", "google__gemini_2_0_flash_001",
            "google__gemini_2_0_flash_lite_preview", "aws__claude_3_haiku", "aws__claude_3_sonnet",
            "aws__claude_3_5_sonnet", "aws__claude_3_7_sonnet", "aws__titan_text_lite",
            "ibm__llama_3_2_90b_vision_instruct", "ibm__llama_4_scout"
        ]
        ai_models_with_desc = {name: all_models_with_desc.get(name, f"{name} (Description not found)")
                               for name in allowed_model_names if name in all_models_with_desc}
        for name in allowed_model_names:
            if name not in ai_models_with_desc:
                 ai_models_with_desc[name] = f"{name} (Description not found)"
                 logger.warning(f"Model '{name}' from allowed list was missing description, added placeholder.")
        ai_model_names = list(ai_models_with_desc.keys())
        ai_model_options = list(ai_models_with_desc.values())
        if "categorization_ai_model" not in st.session_state:
            st.session_state.categorization_ai_model = ai_model_names[0]
        current_model_name = st.session_state.categorization_ai_model
        if current_model_name not in ai_model_names:
            logger.warning(f"Previously selected categorization model '{current_model_name}' is not allowed. Defaulting to '{ai_model_names[0]}'.")
            current_model_name = ai_model_names[0]
            st.session_state.categorization_ai_model = current_model_name
        try:
            current_model_desc = ai_models_with_desc.get(current_model_name, ai_model_options[0])
            selected_index = ai_model_options.index(current_model_desc)
        except (ValueError, KeyError):
            logger.error(f"Error finding index for categorization model '{current_model_name}'. Defaulting to first model.")
            selected_index = 0
            current_model_name = ai_model_names[selected_index]
            st.session_state.categorization_ai_model = current_model_name
        selected_model_desc = st.selectbox(
            "Select AI Model for Categorization",
            options=ai_model_options,
            index=selected_index,
            key="ai_model_select_cat",
            help="Choose the AI model for categorization. Only models supported by the Q&A endpoint are listed."
        )
        selected_model_name = ""
        for name, desc in ai_models_with_desc.items():
            if desc == selected_model_desc:
                selected_model_name = name
                break
        st.session_state.categorization_ai_model = selected_model_name
        selected_model = selected_model_name
        
        st.write("### Categorization Options")
        col1_opt, col2_opt = st.columns(2)
        with col1_opt:
            use_two_stage = st.checkbox(
                "Use two-stage categorization",
                value=True,
                key="use_two_stage_cat",
                help="When enabled, documents with low confidence will undergo a second analysis"
            )
            use_consensus = st.checkbox(
                "Use multi-model consensus",
                value=False,
                key="use_consensus_cat",
                help="When enabled, multiple AI models will be used and their results combined for more accurate categorization"
            )
        with col2_opt:
            confidence_threshold = st.slider(
                "Confidence threshold for second-stage",
                min_value=0.0,
                max_value=1.0,
                value=0.6,
                step=0.05,
                key="confidence_threshold_cat",
                help="Documents with confidence below this threshold will undergo second-stage analysis",
                disabled=not use_two_stage
            )
            consensus_models = []
            if use_consensus:
                selected_consensus_descs = st.multiselect(
                    "Select models for consensus",
                    options=ai_model_options,
                    default=[ai_model_options[0], ai_model_options[1]] if len(ai_model_options) > 1 else ai_model_options[:1],
                    help="Select 2-3 models for best results (more models will increase processing time)",
                    key="consensus_models_multiselect"
                )
                consensus_models = []
                for desc in selected_consensus_descs:
                    for name, description in ai_models_with_desc.items():
                        if description == desc:
                            consensus_models.append(name)
                            break
                if len(consensus_models) < 1:
                    st.warning("Please select at least one model for consensus categorization")
        
        col1_ctrl, col2_ctrl = st.columns(2)
        with col1_ctrl:
            start_button = st.button("Start Categorization", key="start_categorization_button_cat", use_container_width=True)
        with col2_ctrl:
            cancel_button = st.button("Cancel Categorization", key="cancel_categorization_button_cat", use_container_width=True)
        
        if start_button:
            current_doc_types = st.session_state.get("document_types", [])
            valid_categories = [dtype["name"] for dtype in current_doc_types if isinstance(dtype, dict) and "name" in dtype]
            document_types_with_desc = [dtype for dtype in current_doc_types if isinstance(dtype, dict) and "name" in dtype and "description" in dtype]

            if not valid_categories:
                 st.error("Cannot start categorization: No valid document types defined in Settings.")
            else:
                with st.spinner("Categorizing documents..."):
                    st.session_state.document_categorization = {
                        "is_categorized": False,
                        "results": {},
                        "errors": {}
                    }
                    
                    for file in st.session_state.selected_files:
                        file_id = file["id"]
                        file_name = file["name"]
                        
                        try:
                            if use_consensus and consensus_models:
                                consensus_results = []
                                model_progress = st.progress(0)
                                model_status = st.empty()
                                for i, model_name_iter in enumerate(consensus_models):
                                    model_status.text(f"Processing with {model_name_iter}...")
                                    result = categorize_document(file_id, model_name_iter, document_types_with_desc)
                                    # Store model name with result for display in reasoning
                                    result["model_name"] = model_name_iter
                                    consensus_results.append(result)
                                    model_progress.progress((i + 1) / len(consensus_models))
                                model_progress.empty()
                                model_status.empty()
                                result = combine_categorization_results(consensus_results, valid_categories, consensus_models)
                            else:
                                result = categorize_document(file_id, selected_model, document_types_with_desc)
                                if use_two_stage and result["confidence"] < confidence_threshold:
                                    st.info(f'Low confidence ({result["confidence"]:.2f}) for {file_name}, performing detailed analysis...')
                                    detailed_result = categorize_document_detailed(file_id, selected_model, result["document_type"], document_types_with_desc)
                                    result = {
                                        "document_type": detailed_result["document_type"],
                                        "confidence": detailed_result["confidence"],
                                        "reasoning": detailed_result["reasoning"],
                                        "first_stage_type": result["document_type"],
                                        "first_stage_confidence": result["confidence"],
                                        "original_response": detailed_result.get("original_response", "")
                                    }
                            
                            document_features = extract_document_features(file_id)
                            multi_factor_confidence = calculate_multi_factor_confidence(
                                result["confidence"],
                                document_features,
                                result["document_type"],
                                result.get("reasoning", ""),
                                valid_categories
                            )
                            calibrated_confidence = apply_confidence_calibration(
                                result["document_type"],
                                multi_factor_confidence.get("overall", result["confidence"]) 
                            )
                            
                            st.session_state.document_categorization["results"][file_id] = {
                                "file_id": file_id,
                                "file_name": file_name,
                                "document_type": result["document_type"],
                                "confidence": result["confidence"],
                                "multi_factor_confidence": multi_factor_confidence, 
                                "calibrated_confidence": calibrated_confidence, 
                                "reasoning": result["reasoning"],
                                "original_response": result.get("original_response", ""),
                                "first_stage_type": result.get("first_stage_type"),
                                "first_stage_confidence": result.get("first_stage_confidence"),
                                "document_features": document_features
                            }
                        except Exception as e:
                            logger.error(f"Error categorizing document {file_name}: {str(e)}")
                            st.session_state.document_categorization["errors"][file_id] = {
                                "file_id": file_id,
                                "file_name": file_name,
                                "error": str(e)
                            }
                    
                    st.session_state.document_categorization["results"] = apply_confidence_thresholds(
                        st.session_state.document_categorization["results"]
                    )
                    st.session_state.document_categorization["is_categorized"] = True
                    num_processed = len(st.session_state.document_categorization["results"])
                    num_errors = len(st.session_state.document_categorization["errors"])
                    if num_errors == 0:
                        st.success(f"Categorization complete! Processed {num_processed} files.")
                    else:
                        st.warning(f"Categorization complete! Processed {num_processed} files with {num_errors} errors.")
        
        if st.session_state.document_categorization.get("is_categorized", False):
            display_categorization_results()
    
    with tab2: # Settings Tab
        st.write("### Settings")
        st.write("#### Document Types Configuration")
        configure_document_types()

        st.write("#### Confidence Configuration")
        configure_confidence_thresholds()
        with st.expander("Confidence Validation", expanded=False):
            validate_confidence_with_examples()

def configure_document_types():
    """
    Configure user-defined document types with descriptions.
    """
    st.write("Define custom document types and their descriptions for categorization:")
    
    indices_to_delete = []
    for i, doc_type_dict in enumerate(st.session_state.document_types):
        is_other_type = doc_type_dict.get("name") == "Other"
        
        with st.container():
            st.markdown(f"**Document Type {i+1}**")
            col1, col2 = st.columns([3, 1])
            with col1:
                current_name = doc_type_dict.get("name", "")
                new_name = st.text_input(
                    f"Name##{i}",
                    value=current_name, 
                    key=f"doc_type_name_{i}", 
                    disabled=is_other_type, 
                    help="The name of the document category."
                )
                if new_name != current_name and not is_other_type:
                    if any(d["name"] == new_name for j, d in enumerate(st.session_state.document_types) if i != j):
                        st.warning(f"Document type name '{new_name}' already exists.")
                    else:
                        st.session_state.document_types[i]["name"] = new_name
                        logger.info(f"Updated document type name at index {i} to: {new_name}")
                        st.rerun()

                current_desc = doc_type_dict.get("description", "")
                new_desc = st.text_area(
                    f"Description##{i}",
                    value=current_desc, 
                    key=f"doc_type_desc_{i}", 
                    disabled=is_other_type, 
                    height=100,
                    help="Provide a clear description for the AI to understand this category."
                )
                if new_desc != current_desc and not is_other_type:
                    st.session_state.document_types[i]["description"] = new_desc
                    logger.info(f"Updated document type description at index {i}")
                    st.rerun()

            with col2:
                st.write("&nbsp;") 
                if st.button("Delete", key=f"delete_type_{i}", disabled=is_other_type):
                    indices_to_delete.append(i)
                    logger.info(f"Marked document type at index {i} for deletion.")
            st.markdown("---")

    if indices_to_delete:
        indices_to_delete.sort(reverse=True)
        for index in indices_to_delete:
            deleted_type = st.session_state.document_types.pop(index)
            logger.info(f"Deleted document type: {deleted_type.get('name')}")
        st.rerun()

    st.write("**Add New Document Type**")
    new_type_name = st.text_input("New Type Name", key="new_doc_type_name_input")
    new_type_desc = st.text_area("New Type Description", key="new_doc_type_desc_input", height=100)
    
    if st.button("Add Document Type", key="add_doc_type_button"):
      if new_type_name:
        if any(d["name"] == new_type_name for d in st.session_state.document_types):
            st.warning(f"Document type name '{new_type_name}' already exists.")
        else:
            new_doc_type = {"name": new_type_name, "description": new_type_desc}
            st.session_state.document_types.append(new_doc_type)
            logger.info(f"Added new document type: {new_doc_type}")
            st.rerun()
      else:
        st.warning("New type name cannot be empty.")
    
    if st.button("Reset to Defaults", key="reset_doc_types_button"):
        st.session_state.document_types = [
            {"name": "Sales Contract", "description": "Contracts related to sales agreements and terms."},
            {"name": "Invoices", "description": "Billing documents issued by a seller to a buyer, indicating quantities, prices for products or services."},
            {"name": "Tax", "description": "Documents related to government taxation (e.g., tax forms, filings, receipts)."},
            {"name": "Financial Report", "description": "Reports detailing the financial status or performance of an entity (e.g., balance sheets, income statements)."},
            {"name": "Employment Contract", "description": "Agreements outlining terms and conditions of employment between an employer and employee."},
            {"name": "PII", "description": "Documents containing Personally Identifiable Information that needs careful handling."},
            {"name": "Other", "description": "Any document not fitting into the specific categories above."}
        ]
        logger.info("Reset document types to default values.")
        st.rerun()

def display_categorization_results():
    """
    Display categorization results with enhanced confidence visualization
    """
    st.write("### Categorization Results")
    results = st.session_state.document_categorization.get("results", {})
    if not results:
        st.info("No categorization results available.")
        return
    
    tab_table, tab_detailed = st.tabs(["Table View", "Detailed View"])
    
    with tab_table:
        results_data = []
        for file_id, result in results.items():
            status = result.get("status", "Review")
            confidence = result.get("calibrated_confidence", result.get("multi_factor_confidence", {}).get("overall", result.get("confidence", 0.0)))
            if confidence >= 0.8: confidence_level, confidence_color = "High", "green"
            elif confidence >= 0.6: confidence_level, confidence_color = "Medium", "orange"
            else: confidence_level, confidence_color = "Low", "red"
            results_data.append({
                "File Name": result["file_name"],
                "Document Type": result["document_type"],
                "Confidence": f"<span style='color: {confidence_color};'>{confidence_level} ({confidence:.2f})</span>",
                "Status": status
            })
        if results_data:
            df = pd.DataFrame(results_data)
            st.markdown(df.to_html(escape=False, index=False), unsafe_allow_html=True)
    
    with tab_detailed:
        current_doc_types_for_dropdown = [dtype["name"] for dtype in st.session_state.get("document_types", []) if isinstance(dtype, dict) and "name" in dtype]
        if not current_doc_types_for_dropdown:
            current_doc_types_for_dropdown = ["Other"]

        for file_id, result in results.items():
            with st.container():
                st.write(f"#### {result['file_name']}")
                col1_detail, col2_detail = st.columns([2, 1])
                with col1_detail:
                    st.write(f"**Category:** {result['document_type']}")
                    
                    logger.info(f"Debug Detailed View: File {file_id}. Checking 'multi_factor_confidence'. Key present: {'multi_factor_confidence' in result}. Value: {result.get('multi_factor_confidence')}")
                    if "multi_factor_confidence" in result and result["multi_factor_confidence"]:
                        logger.info(f"Debug Detailed View: File {file_id}. Rendering 'multi_factor_confidence' using display_confidence_visualization.")
                        with st.expander("Confidence Breakdown", expanded=True):
                             display_confidence_visualization(result["multi_factor_confidence"], result["document_type"], container=st)
                    else: 
                        logger.info(f"Debug Detailed View: File {file_id}. 'multi_factor_confidence' is MISSING or EMPTY. Falling back to simple confidence display.")
                        confidence = result.get("confidence", 0.0)
                        if confidence >= 0.8: level, color = "High", "#28a745"
                        elif confidence >= 0.6: level, color = "Medium", "#ffc107"
                        else: level, color = "Low", "#dc3545"
                        st.markdown(f"**Confidence:** <span style='color:{color};'>{level} ({confidence:.2f})</span>", unsafe_allow_html=True)
                    
                    with st.expander("Reasoning", expanded=False):
                        st.write(result.get("reasoning", "No reasoning provided"))
                    if result.get("first_stage_type"):
                        with st.expander("First-Stage Results", expanded=False):
                            st.write(f"**First-stage category:** {result['first_stage_type']}")
                            st.write(f"**First-stage confidence:** {result['first_stage_confidence']:.2f}")
                with col2_detail:
                    st.write("**Override Category:**")
                    try:
                        current_index = current_doc_types_for_dropdown.index(result["document_type"])
                    except ValueError:
                        current_index = 0

                    new_category = st.selectbox(
                        "Select category",
                        options=current_doc_types_for_dropdown,
                        index=current_index,
                        key=f"override_cat_select_{file_id}"
                    )
                    if st.button("Apply Override", key=f"apply_override_button_{file_id}"):
                        save_categorization_feedback(file_id, result["document_type"], new_category)
                        st.session_state.document_categorization["results"][file_id]["document_type"] = new_category
                        st.session_state.document_categorization["results"][file_id]["confidence"] = 1.0 
                        st.session_state.document_categorization["results"][file_id]["calibrated_confidence"] = 1.0
                        st.session_state.document_categorization["results"][file_id]["multi_factor_confidence"] = {"overall": 1.0, "ai_reported": 1.0, "response_quality": 1.0, "category_specificity": 1.0, "reasoning_quality": 1.0, "document_features_match": 1.0}
                        st.session_state.document_categorization["results"][file_id]["reasoning"] += "\n\nManually overridden by user."
                        st.session_state.document_categorization["results"][file_id]["status"] = "Accepted"
                        st.success(f"Category updated to {new_category} for {result['file_name']}")
                        st.rerun()
                    
                    preview_url = get_document_preview_url(file_id)
                    if preview_url:
                        if st.button("Preview Document", key=f"preview_doc_button_{file_id}"):
                            st.markdown(f"[Open Preview in New Tab]({preview_url})", unsafe_allow_html=True)
                    else:
                        st.caption("Preview not available for this file.")

                st.markdown("---")
        
        if st.button("Proceed to Next Step (e.g., Apply Metadata)", key="proceed_to_metadata_cat"):
            st.info("Functionality to proceed to the next step (e.g., applying metadata) is not yet implemented in this module.")

def categorize_document(file_id: str, model: str, document_types_with_desc: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Categorize a document using Box AI (adapted for dynamic categories)
    """
    access_token = None
    if hasattr(st.session_state.client, "_oauth"):
        access_token = st.session_state.client._oauth.access_token
    elif hasattr(st.session_state.client, "auth") and hasattr(st.session_state.client.auth, "access_token"):
        access_token = st.session_state.client.auth.access_token
    if not access_token:
        raise ValueError("Could not retrieve access token from client")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    valid_categories = [dtype["name"] for dtype in document_types_with_desc]
    category_options_text = "\n".join([f"- {dtype['name']}: {dtype['description']}" for dtype in document_types_with_desc])

    prompt = (
        f"Analyze this document and determine which category it belongs to from the following options:\n"
        f"{category_options_text}\n\n"
        f"Provide your answer ONLY in the following format (exactly two lines, followed by reasoning on a new line):\n"
        f"Category: [selected category name]\n"
        f"Confidence: [confidence score between 0.0 and 1.0, where 1.0 is highest confidence]\n"
        f"Reasoning: [detailed explanation of your categorization, including key features of the document that support this categorization]"
    )
    logger.info(f"Box AI Request Prompt for file {file_id} (model: {model}):\n{prompt}")

    api_url = "https://api.box.com/2.0/ai/ask"
    request_body = {
        "mode": "single_item_qa",
        "prompt": prompt,
        "items": [{"type": "file", "id": file_id}],
        "ai_agent": {"type": "ai_agent_ask", "basic_text": {"model": model, "mode": "default"}}
    }
    try:
        logger.info(f"Making Box AI call for file {file_id} with model {model}")
        response = requests.post(api_url, headers=headers, json=request_body, timeout=120)
        response.raise_for_status()
        response_data = response.json()
        logger.info(f"Box AI response for {file_id}: {json.dumps(response_data)}")
        if "answer" in response_data and response_data["answer"]:
            original_response = response_data["answer"]
            document_type, confidence, reasoning = parse_categorization_response(original_response, valid_categories)
            return {
                "document_type": document_type, 
                "confidence": confidence, 
                "reasoning": reasoning,
                "original_response": original_response
            }
        else:
            logger.warning(f"No answer field or empty answer in Box AI response for file {file_id}. Response: {response_data}")
            return {"document_type": "Other", "confidence": 0.0, "reasoning": "Could not determine document type (No answer from AI)"}
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during Box AI API call for file {file_id}: {str(e)}")
        error_details = str(e)
        if hasattr(e, "response") and e.response is not None:
            try:
                error_content = e.response.json()
                error_details = error_content.get("message", json.dumps(error_content))
            except json.JSONDecodeError:
                error_details = e.response.text
        raise Exception(f"Error categorizing document {file_id}: {error_details}")
    except Exception as e:
        logger.exception(f"Unexpected error during Box AI call or parsing for file {file_id}: {str(e)}")
        raise Exception(f"Unexpected error categorizing document {file_id}: {str(e)}")

def categorize_document_detailed(file_id: str, model: str, initial_category: str, document_types_with_desc: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Perform a more detailed categorization (adapted for dynamic categories)
    """
    access_token = None
    if hasattr(st.session_state.client, "_oauth"):
        access_token = st.session_state.client._oauth.access_token
    elif hasattr(st.session_state.client, "auth") and hasattr(st.session_state.client.auth, "access_token"):
        access_token = st.session_state.client.auth.access_token
    if not access_token:
        raise ValueError("Could not retrieve access token from client for detailed categorization")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    valid_categories = [dtype["name"] for dtype in document_types_with_desc]
    category_options_text = "\n".join([f"- {dtype['name']}: {dtype['description']}" for dtype in document_types_with_desc])

    prompt = (
        f"The document was initially categorized as '{initial_category}'. " 
        f"Please perform a more detailed analysis. Consider the following categories and their descriptions:\n" 
        f"{category_options_text}\n\n" 
        f"For each category listed above, provide a score from 0-10 indicating how well the document matches that category, " 
        f"along with specific evidence from the document supporting your score.\n\n" 
        f"Finally, provide your definitive categorization ONLY in the following format (exactly two lines, followed by reasoning on a new line):\n" 
        f"Category: [selected category name]\n"
        f"Confidence: [confidence score between 0.0 and 1.0, where 1.0 is highest confidence]\n"
        f"Reasoning: [detailed explanation with specific evidence from the document supporting your final choice, referencing the scoring and initial category if relevant]"
    )
    logger.info(f"Box AI Detailed Request Prompt for file {file_id} (model: {model}):\n{prompt}")

    api_url = "https://api.box.com/2.0/ai/ask"
    request_body = {
        "mode": "single_item_qa",
        "prompt": prompt,
        "items": [{"type": "file", "id": file_id}],
        "ai_agent": {"type": "ai_agent_ask", "basic_text": {"model": model, "mode": "default"}}
    }
    try:
        logger.info(f"Making detailed Box AI call for file {file_id} with model {model}")
        response = requests.post(api_url, headers=headers, json=request_body, timeout=180)
        response.raise_for_status()
        response_data = response.json()
        logger.info(f"Detailed Box AI response for {file_id}: {json.dumps(response_data)}")
        if "answer" in response_data and response_data["answer"]:
            original_response = response_data["answer"]
            document_type, confidence, reasoning = parse_categorization_response(original_response, valid_categories)
            if confidence > 0.0:
                 confidence = min(confidence * 1.1, 1.0) 
            else:
                 confidence = 0.5 
            return {
                "document_type": document_type, 
                "confidence": confidence, 
                "reasoning": reasoning,
                "original_response": original_response
            }
        else:
            logger.warning(f"No answer field or empty answer in detailed Box AI response for file {file_id}. Response: {response_data}")
            return {"document_type": initial_category, "confidence": 0.3, "reasoning": "Could not determine document type in detailed analysis (No answer from AI)"}
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during detailed Box AI API call for file {file_id}: {str(e)}")
        error_details = str(e)
        if hasattr(e, "response") and e.response is not None:
            try:
                error_content = e.response.json()
                error_details = error_content.get("message", json.dumps(error_content))
            except json.JSONDecodeError:
                error_details = e.response.text
        raise Exception(f"Error in detailed categorization for document {file_id}: {error_details}")
    except Exception as e:
        logger.exception(f"Unexpected error during detailed Box AI call or parsing for file {file_id}: {str(e)}")
        raise Exception(f"Unexpected error in detailed categorization for document {file_id}: {str(e)}")

def parse_categorization_response(response_text: str, valid_categories: List[str]) -> Tuple[str, float, str]:
    """
    Fixed parsing function to extract category, confidence, and reasoning from AI response.
    Uses simple string handling methods instead of regex to avoid Python 3.11+ issues.
    """
    # Default values
    document_type = "Other" 
    confidence = 0.0      
    reasoning = ""        

    logger.info(f"Parsing AI response: {response_text[:150]}...")

    try:
        # Split the response into lines
        lines = response_text.split('\n')
        
        # Extract category, confidence, and reasoning using string operations
        category_line = None
        confidence_line = None
        reasoning_start_index = -1
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
                
            # Find the category line
            if line.lower().startswith("category:"):
                category_line = line
            
            # Find the confidence line
            elif line.lower().startswith("confidence:"):
                confidence_line = line
            
            # Find the reasoning line
            elif line.lower().startswith("reasoning:"):
                reasoning_start_index = i
                break
        
        # Process category
        if category_line:
            extracted_category = category_line.split(":", 1)[1].strip() if ":" in category_line else ""
            logger.info(f"Successfully extracted category from response: '{extracted_category}'")
            
            # Check for exact match (case insensitive)
            found_match = False
            for valid_cat in valid_categories:
                if valid_cat.lower() == extracted_category.lower():
                    document_type = valid_cat
                    logger.info(f"Exact match found for category: {valid_cat}")
                    found_match = True
                    break
            
            # If no exact match, check for partial match
            if not found_match and extracted_category:
                for valid_cat in valid_categories:
                    if valid_cat != "Other" and (valid_cat.lower() in extracted_category.lower() or 
                                               extracted_category.lower() in valid_cat.lower()):
                        document_type = valid_cat
                        logger.warning(f"Partial match for category: extracted '{extracted_category}', matched with '{valid_cat}'.")
                        found_match = True
                        break
            
            # If the extracted category is explicitly "Other", use it
            if not found_match and extracted_category.lower() == "other":
                document_type = "Other"
                found_match = True
                logger.info("Category is explicitly 'Other'")
        else:
            logger.warning("Could not find a category line in the response.")
        
        # Process confidence
        if confidence_line:
            confidence_parts = confidence_line.split(":", 1)
            if len(confidence_parts) > 1:
                confidence_value = confidence_parts[1].strip()
                try:
                    confidence = float(confidence_value)
                    confidence = max(0.0, min(1.0, confidence))  # Ensure between 0 and 1
                    logger.info(f"Successfully extracted confidence: {confidence}")
                except ValueError:
                    logger.warning(f"Could not convert '{confidence_value}' to a float.")
        else:
            logger.warning("Could not find a confidence line in the response.")
            # If we found a valid category but no confidence, use a default value
            if document_type != "Other":
                confidence = 0.7
                logger.info(f"Using default confidence value of 0.7 for category '{document_type}'")
        
        # Process reasoning
        if reasoning_start_index >= 0 and reasoning_start_index+1 < len(lines):
            # Take all lines after the reasoning label
            reasoning_lines = lines[reasoning_start_index+1:]
            reasoning = "\n".join(reasoning_lines).strip()
            logger.info(f"Successfully extracted reasoning (first 100 chars): {reasoning[:100]}")
        else:
            # If no explicit reasoning section, use remaining text
            non_header_lines = []
            for line in lines:
                line = line.strip()
                if not line.lower().startswith("category:") and not line.lower().startswith("confidence:"):
                    non_header_lines.append(line)
            
            reasoning = "\n".join(non_header_lines).strip()
            if reasoning:
                logger.info("Using non-header text as reasoning.")
            else:
                reasoning = "No reasoning provided in the AI response."
                logger.warning("No reasoning found in the response.")
                
        # Fall back to the original text as reasoning if all else failed
        if not reasoning:
            reasoning = response_text
            logger.warning("Using full response text as reasoning as no specific reasoning was found.")

    except Exception as e:
        logger.error(f"Error parsing categorization response: {str(e)}")
        document_type = "Other"
        confidence = 0.0
        reasoning = f"Error parsing response: {str(e)}\n\nOriginal response: {response_text}"

    logger.info(f"Final parsing results - Category: {document_type}, Confidence: {confidence:.2f}")
    
    return document_type, confidence, reasoning

def extract_document_features(file_id: str) -> Dict[str, Any]:
    """Extract features from a document to aid in categorization"""
    client = st.session_state.client
    try:
        file_info = client.file(file_id).get(fields=["size", "name", "extension", "type"])
        features = {
            "extension": file_info.extension.lower() if file_info.extension else "",
            "size_kb": file_info.size / 1024 if file_info.size else 0,
            "file_type": file_info.type
        }
        features["text_content_preview"] = f"{file_info.name} (type: {file_info.type})" 
        return features
    except Exception as e:
        logger.error(f"Error extracting document features for {file_id}: {str(e)}")
        return {"extension": "", "size_kb": 0, "file_type": "", "text_content_preview": ""}

def calculate_multi_factor_confidence(
    ai_reported_confidence: float,
    document_features: dict,
    category: str,
    reasoning_text: str,
    all_document_types: List[str]
) -> dict:
    """Calculate a multi-factor confidence score"""
    confidence_factors = {
        "ai_reported": ai_reported_confidence,
        "response_quality": 0.5,
        "category_specificity": 0.5,
        "reasoning_quality": 0.5,
        "document_features_match": 0.5
    }

    if category != "Other" and ai_reported_confidence > 0.0 and reasoning_text:
        confidence_factors["response_quality"] = 0.8
    if "error parsing response" in reasoning_text.lower() or "could not determine" in reasoning_text.lower():
        confidence_factors["response_quality"] = 0.2
    
    if category != "Other" and category in all_document_types:
        confidence_factors["category_specificity"] = 0.9
    elif category == "Other":
        confidence_factors["category_specificity"] = 0.3

    reasoning_len = len(reasoning_text)
    if reasoning_len > 100: confidence_factors["reasoning_quality"] = 0.8
    elif reasoning_len > 50: confidence_factors["reasoning_quality"] = 0.6
    else: confidence_factors["reasoning_quality"] = 0.4
    if "evidence" in reasoning_text.lower() or "feature" in reasoning_text.lower():
        confidence_factors["reasoning_quality"] = min(1.0, confidence_factors["reasoning_quality"] + 0.1)

    weights = {
        "ai_reported": 0.4,
        "response_quality": 0.15,
        "category_specificity": 0.2,
        "reasoning_quality": 0.15,
        "document_features_match": 0.1 
    }
    
    overall_confidence = sum(
        confidence_factors[factor] * weights[factor]
        for factor in confidence_factors
    )
    overall_confidence = max(0.0, min(1.0, overall_confidence))
    confidence_factors["overall"] = overall_confidence
    return confidence_factors

def apply_confidence_calibration(category: str, confidence: float) -> float:
    """Placeholder for confidence calibration"""
    return confidence

def display_confidence_visualization(confidence_data: dict, category: str, container=None):
    """Display a comprehensive confidence visualization with breakdown, bars, and help icons."""
    if container is None: 
        container = st
    
    overall_confidence = confidence_data.get("overall", 0.0)
    
    if overall_confidence >= 0.8: 
        level, color = "High", "#28a745"  # Green
    elif overall_confidence >= 0.6: 
        level, color = "Medium", "#ffc107"  # Yellow
    else: 
        level, color = "Low", "#dc3545"  # Red

    # Create confidence meter with enhanced styling
    container.markdown(
        f"""
        <div style="margin-bottom: 10px;">
            <div style="display: flex; align-items: center; margin-bottom: 5px;">
                <div style="font-weight: bold; margin-right: 10px;">Overall Confidence:</div>
                <div style="font-weight: bold; color: {color};">{level} ({overall_confidence:.2f})</div>
            </div>
            <div style="width: 100%; background-color: #f0f0f0; height: 10px; border-radius: 5px; overflow: hidden;">
                <div style="width: {overall_confidence*100}%; background-color: {color}; height: 100%;"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    factors_display = {
        "ai_reported": "AI Model",
        "response_quality": "Response Quality",
        "category_specificity": "Category Specificity",
        "reasoning_quality": "Reasoning Quality",
        "document_features_match": "Document Features Match"
    }
    
    explanations = get_confidence_explanation(confidence_data, category)

    # Display confidence factors with enhanced styling
    for factor_key, factor_name in factors_display.items():
        value = confidence_data.get(factor_key)
        
        if value is not None:
            # Determine factor color
            if value >= 0.8:
                factor_color = "#28a745"  # Green
            elif value >= 0.6:
                factor_color = "#ffc107"  # Yellow
            else:
                factor_color = "#dc3545"  # Red
            
            # Display factor with styled meter and help icon
            container.markdown(
                f"""
                <div style="display: flex; align-items: center; margin-bottom: 5px;">
                    <div style="width: 150px;">{factor_name}:</div>
                    <div style="flex-grow: 1; background-color: #f0f0f0; height: 8px; border-radius: 4px; overflow: hidden; margin: 0 10px;">
                        <div style="width: {value*100}%; background-color: {factor_color}; height: 100%;"></div>
                    </div>
                    <div style="width: 40px; text-align: right; color: {factor_color};">{value:.2f}</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            container.markdown(f"- **{factor_name}:** N/A")

    # Display explanations after the meters
    container.markdown("**Confidence Factors Explained:**")
    container.markdown("""
    - **AI Model**: Confidence reported directly by the AI model
    - **Response Quality**: How well-structured the AI response was
    - **Category Specificity**: How specific and definitive the category assignment is
    - **Reasoning Quality**: How detailed and specific the reasoning is
    - **Document Features Match**: How well document features match the assigned category
    """)

def get_confidence_explanation(confidence_data: dict, category: str) -> dict:
    """Generate human-readable explanations of confidence scores."""
    explanations = {"overall": "", "factors": {}}
    overall_confidence = confidence_data.get("overall", 0.0)

    if overall_confidence >= 0.8: explanations["overall"] = f"The system is highly confident that the document is a '{category}'."
    elif overall_confidence >= 0.6: explanations["overall"] = f"The system has medium confidence that the document is a '{category}'. Manual review is recommended."
    else: explanations["overall"] = f"The system has low confidence that the document is a '{category}'. Manual review is strongly recommended."

    explanations["factors"]["ai_reported"] = f"The AI model initially reported a confidence of {confidence_data.get('ai_reported', 0.0):.2f}. This is the raw confidence score from the AI model before any adjustments."
    explanations["factors"]["response_quality"] = f"The quality of the AI response structure was assessed as {confidence_data.get('response_quality', 0.0):.2f}. Good structure includes clear category, confidence, and reasoning. Poor structure or parsing errors lower this score."
    explanations["factors"]["category_specificity"] = f"The specificity of the assigned category ('{category}') contributed {confidence_data.get('category_specificity', 0.0):.2f} to the score. Specific, non-'Other' categories score higher, reflecting a more precise classification."
    explanations["factors"]["reasoning_quality"] = f"The AI's reasoning quality was rated {confidence_data.get('reasoning_quality', 0.0):.2f}, based on the length and presence of keywords like 'evidence' or 'feature'. More detailed and relevant reasoning increases this score."
    explanations["factors"]["document_features_match"] = f"The match between document features (e.g., file extension, size) and the typical characteristics of the assigned category was {confidence_data.get('document_features_match', 0.0):.2f}. This is a simplified factor and may be expanded in future versions."
    
    return explanations

def configure_confidence_thresholds():
    """Configure confidence thresholds"""
    if "confidence_thresholds" not in st.session_state:
        st.session_state.confidence_thresholds = {"auto_accept": 0.85, "verification": 0.6, "rejection": 0.4}
    
    st.session_state.confidence_thresholds["auto_accept"] = st.slider(
        "Auto-Accept Threshold", 0.0, 1.0, st.session_state.confidence_thresholds["auto_accept"], 0.05,
        help="Documents with calibrated confidence above this will be marked 'Accepted'."
    )
    st.session_state.confidence_thresholds["verification"] = st.slider(
        "Verification Threshold", 0.0, 1.0, st.session_state.confidence_thresholds["verification"], 0.05,
        help="Documents with calibrated confidence below Auto-Accept but above this will be marked 'Needs Verification'."
    )
    st.session_state.confidence_thresholds["rejection"] = st.slider(
        "Rejection Threshold", 0.0, 1.0, st.session_state.confidence_thresholds["rejection"], 0.05,
        help="Documents with calibrated confidence below this will be marked 'Rejected' (Not currently used for status, but available)."
    )

def apply_confidence_thresholds(results: Dict[str, Dict]) -> Dict[str, Dict]:
    """Apply confidence thresholds to categorization results"""
    thresholds = st.session_state.confidence_thresholds
    for file_id, result in results.items():
        confidence = result.get("calibrated_confidence", result.get("multi_factor_confidence", {}).get("overall", result.get("confidence", 0.0)))
        if confidence >= thresholds["auto_accept"]:
            result["status"] = "Accepted"
        elif confidence >= thresholds["verification"]:
            result["status"] = "Needs Verification"
        else:
            result["status"] = "Review Suggested"
    return results

def save_categorization_feedback(file_id: str, original_category: str, new_category: str, rating: Optional[int] = None, comments: Optional[str] = None):
    """Save user feedback for categorization (Placeholder)"""
    logger.info(f"Feedback for {file_id}: Original='{original_category}', New='{new_category}', Rating={rating}, Comments='{comments}'")

def collect_user_feedback(file_id, result_data):
    """UI for collecting user feedback (Placeholder)"""
    st.write("Rate the categorization:")
    cols = st.columns(5)
    rating = 0
    for i in range(5):
        if cols[i].button(f"{i+1} 'star:", key=f"rating_{file_id}_{i}"):
            rating = i + 1
    comments = st.text_area("Comments (optional)", key=f"comments_{file_id}")
    if rating > 0:
        save_categorization_feedback(file_id, result_data["document_type"], result_data["document_type"], rating, comments)
        st.success("Feedback submitted!")

def get_document_preview_url(file_id: str) -> Optional[str]:
    """
    Get document preview URL - fixed to properly handle the expiring_embed_link structure
    """
    try:
        client = st.session_state.client
        file_info = client.file(file_id).get(fields=["expiring_embed_link"])
        
        # Check if expiring_embed_link is a dict
        if isinstance(file_info.expiring_embed_link, dict):
            if "url" in file_info.expiring_embed_link:
                return file_info.expiring_embed_link["url"]
        # Check if it's an object with url attribute
        elif hasattr(file_info.expiring_embed_link, "url"):
            return file_info.expiring_embed_link.url
        # Check for nested structure
        elif isinstance(file_info.expiring_embed_link, dict) and "url" in file_info.expiring_embed_link:
            return file_info.expiring_embed_link["url"]
        
        logger.error(f"Unexpected expiring_embed_link structure: {str(file_info.expiring_embed_link)}")
        return None
    except Exception as e:
        logger.error(f"Could not get preview URL for {file_id}: {e}")
        return None

def combine_categorization_results(results: List[Dict[str, Any]], valid_categories: List[str], model_names: List[str] = None) -> Dict[str, Any]:
    """
    Fixed weighted voting implementation to correctly combine results from multiple models
    
    Args:
        results: List of categorization results from different models
        valid_categories: List of valid document categories
        model_names: List of model names corresponding to results
        
    Returns:
        dict: Combined categorization result with weighted voting
    """
    if not results: 
        return {"document_type": "Other", "confidence": 0.0, "reasoning": "No consensus results"}
    
    logger.info(f"Combining results from {len(results)} models using weighted voting")
    
    # Use weighted voting based on confidence scores
    votes = {}
    model_details = []
    
    # Store original AI responses for inclusion in the combined reasoning
    original_responses = []
    
    for i, result in enumerate(results):
        doc_type = result.get("document_type", "Other")
        confidence = result.get("confidence", 0.0)
        reasoning = result.get("reasoning", "")
        original_response = result.get("original_response", "")
        
        # Get model name if available
        model_name = "Unknown Model"
        if model_names and i < len(model_names):
            model_name = model_names[i]
        elif "model_name" in result:
            model_name = result["model_name"]
            
        # Store model details for reporting
        model_details.append({
            "model": model_name,
            "category": doc_type,
            "confidence": confidence,
            "reasoning": reasoning,
            "original_response": original_response
        })
        
        # Add weighted vote (using confidence as weight)
        if doc_type not in votes:
            votes[doc_type] = 0.0
        votes[doc_type] += confidence
        
        # Keep track of original responses
        if original_response:
            original_responses.append({
                "model": model_name,
                "response": original_response
            })
    
    # Find the category with the highest weighted votes
    if not votes:
        return {"document_type": "Other", "confidence": 0.0, "reasoning": "No valid votes cast by models"}
    
    # Get winning category
    winning_category = max(votes.keys(), key=lambda k: votes[k])
    
    # Calculate normalized confidence (proportion of winning votes to total votes)
    total_votes = sum(votes.values())
    if total_votes > 0:
        winning_confidence = votes[winning_category] / total_votes
    else:
        winning_confidence = 0.0
    
    logger.info(f"Weighted voting results: Winner={winning_category}, Confidence={winning_confidence:.2f}, Vote distribution: {votes}")
    
    # Build detailed reasoning text for display
    if model_names:
        models_text = ", ".join(model_names)
    else:
        models_text = ", ".join([detail["model"] for detail in model_details])
    
    reasoning_parts = []
    for detail in model_details:
        reasoning_parts.append(f"Model vote: {detail['category']} (confidence: {detail['confidence']:.2f}) Reasoning: {detail['reasoning']}")
    
    # Format combined reasoning in structured format as shown in screenshot
    combined_reasoning = (
        f"Consensus from models: {models_text}\n\n"
        f"Combined result from multiple models:\n\n"
        f"Final category: {winning_category} (confidence: {winning_confidence:.2f})\n\n"
        f"Individual model results:\n\n" + "\n\n".join(reasoning_parts)
    )
    
    # For each model, include the original response too
    for i, response_info in enumerate(original_responses):
        combined_reasoning += f"\n\nOriginal response: Category: {model_details[i]['original_response']}"
    
    return {
        "document_type": winning_category,
        "confidence": winning_confidence,
        "reasoning": combined_reasoning,
        "original_responses": original_responses  # Store original responses for display
    }

def validate_confidence_with_examples():
    """UI for validating confidence with example documents (Placeholder)"""
    st.write("Upload example documents to validate confidence scoring (Not Implemented).")
