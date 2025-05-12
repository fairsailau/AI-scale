# Implementation Guide for Enhanced Box AI Metadata Extraction App

## Overview
This guide documents the enhancements made to the Box AI Metadata Extraction application, including the preprocessing step for document categorization, metadata template retrieval, and template selection features.

## New Features

### 1. Document Categorization
A preprocessing step has been added that uses Box AI to analyze documents and categorize them into predefined types:
- Sales Contract
- Invoices
- Tax
- Financial Report
- Employment Contract
- PII (Personally Identifiable Information)
- Other (for documents that don't match the above categories)

### 2. Metadata Template Retrieval
The application now retrieves existing metadata templates from Box and provides functionality to:
- Retrieve all templates at application startup
- Cache templates to avoid unnecessary API calls
- Refresh templates on demand
- Match templates to document types based on categorization results

### 3. Template Selection
The enhanced UI allows users to:
- View document categorization results
- See suggested templates based on document types
- Override suggested templates if needed
- Customize freeform prompts for document types without templates

### 4. Processing Integration
The processing flow has been updated to:
- Use document type-specific templates for structured extraction
- Use customized freeform prompts for document types without templates
- Fall back to default extraction methods when needed

## Implementation Details

### New Modules

#### 1. Document Categorization Module
Location: `/modules/document_categorization.py`

This module implements:
- A new UI page for document categorization
- Box AI integration for document analysis
- Categorization logic for predefined document types
- Storage of categorization results in session state

#### 2. Metadata Template Retrieval Module
Location: `/modules/metadata_template_retrieval.py`

This module implements:
- Functions to retrieve metadata templates from Box
- Template caching and refresh mechanisms
- Template matching logic based on document types
- Helper functions for template format conversion

### Modified Modules

#### 1. Main Application (app.py)
Changes:
- Added Document Categorization to navigation
- Implemented template retrieval at startup
- Added template refresh functionality
- Updated session state initialization

#### 2. Metadata Configuration (metadata_config.py)
Changes:
- Enhanced UI to display document categorization results
- Added document type to template mapping display
- Implemented template override functionality
- Added customizable freeform prompts for document types

#### 3. Processing (processing.py)
Changes:
- Updated to handle document type-specific templates
- Added support for document type-specific freeform prompts
- Enhanced error handling and retry mechanisms
- Improved results display and feedback collection

## Technical Implementation

### Document Categorization
The document categorization feature uses Box AI's freeform extraction API with a specialized prompt:

```python
def categorize_document(file_id, client):
    """
    Use Box AI to categorize a document into predefined types
    """
    # Define document types
    document_types = [
        "Sales Contract", 
        "Invoices", 
        "Tax", 
        "Financial Report", 
        "Employment Contract", 
        "PII"
    ]
    
    # Create prompt for Box AI
    prompt = f"""
    Analyze this document and categorize it into exactly ONE of the following types:
    {', '.join(document_types)}, or "Other" if it doesn't match any of these types.
    
    Provide your answer in JSON format with the following structure:
    {{
        "document_type": "The determined document type",
        "confidence": "A number between 0 and 1 indicating your confidence",
        "reasoning": "Brief explanation of why you categorized it this way"
    }}
    """
    
    # API call implementation...
```

### Metadata Template Retrieval
Templates are retrieved using the Box API and cached in the session state:

```python
def retrieve_templates_by_scope(client, scope):
    """
    Retrieve metadata templates for a specific scope
    """
    templates = []
    next_marker = None
    
    try:
        # Make API calls until all templates are retrieved
        while True:
            # Construct API URL
            api_url = f"https://api.box.com/2.0/metadata_templates/{scope}"
            if next_marker:
                api_url += f"?marker={next_marker}"
            
            # API call implementation...
            
            # Add templates to list
            if 'entries' in data:
                templates.extend(data['entries'])
            
            # Check for next marker
            if 'next_marker' in data and data['next_marker']:
                next_marker = data['next_marker']
            else:
                break
        
        return templates
    
    except Exception as e:
        logger.error(f"Error retrieving {scope} templates: {str(e)}")
        return []
```

### Template Matching
Templates are matched to document types using a keyword-based scoring system:

```python
def match_template_to_document_type(document_type, templates):
    """
    Match a document type to an appropriate metadata template
    """
    # Define mapping of document types to keywords
    type_to_keywords = {
        "Sales Contract": ["sales", "contract", "agreement", "deal"],
        "Invoices": ["invoice", "bill", "payment", "receipt"],
        "Tax": ["tax", "irs", "return", "1099", "w2", "w-2"],
        "Financial Report": ["financial", "report", "statement", "balance", "income"],
        "Employment Contract": ["employment", "hr", "human resources", "employee", "personnel"],
        "PII": ["personal", "pii", "identity", "confidential", "private"]
    }
    
    # Scoring implementation...
```

### Processing Integration
The processing module now checks for document type-specific templates:

```python
# Check if using document type templates
if st.session_state.metadata_config.get("use_document_type_templates", False):
    # Get document type for this file
    document_type = "Other"
    if "document_categorization" in st.session_state and file_id in st.session_state.document_categorization["results"]:
        document_type = st.session_state.document_categorization["results"][file_id].get("document_type", "Other")
    
    # Get template for this document type
    template = None
    if "file_to_template" in st.session_state and file_id in st.session_state.file_to_template:
        template = st.session_state.file_to_template[file_id]
    
    if template:
        # Use structured extraction with template
        # Implementation...
    else:
        # Use freeform extraction with custom prompt for document type
        # Implementation...
```

## User Workflow

1. **Authentication**: User authenticates with Box
2. **File Selection**: User selects files in the File Browser
3. **Document Categorization**: User categorizes documents using Box AI
4. **Template Selection**: User reviews and optionally overrides suggested templates
5. **Processing**: User processes files with the appropriate templates or freeform prompts
6. **Results Review**: User reviews extraction results
7. **Metadata Application**: User applies extracted metadata to Box files

## Configuration Options

### Document Categorization
- **Document Types**: Sales Contract, Invoices, Tax, Financial Report, Employment Contract, PII, Other
- **AI Model**: Can be configured in the metadata configuration page

### Template Selection
- **Use Document Type Templates**: Toggle to use document type-specific templates
- **Template Override**: Option to override suggested templates for each document type
- **Freeform Prompt Customization**: Customize prompts for document types without templates

### Processing
- **Batch Size**: Number of files to process in parallel
- **Max Retries**: Maximum number of retry attempts for failed extractions
- **Retry Delay**: Delay between retry attempts

## Testing
A comprehensive test plan has been created to verify all new features. See `test_plan.md` for details.

## Future Enhancements

1. **Improved Categorization**: Enhance document categorization with machine learning models trained on specific document types
2. **Template Creation**: Add ability to create new metadata templates from within the application
3. **Batch Template Assignment**: Allow assigning templates to multiple files at once
4. **Categorization Feedback**: Implement feedback mechanism for document categorization to improve accuracy over time
5. **Template Versioning**: Track changes to templates and provide version history

## Conclusion
The enhanced Box AI Metadata Extraction application now provides a more streamlined workflow for extracting and applying metadata to Box files. The preprocessing step for document categorization and automatic template matching significantly reduces the manual effort required to process different document types.
