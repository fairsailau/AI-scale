# Box Metadata AI: LLM Self-Reporting Confidence Implementation

## Overview

This document provides a comprehensive guide to the implementation of confidence scoring in the Box Metadata AI application. The solution uses Box AI agent overrides to instruct the AI model to self-report confidence levels for each extracted metadata field.

## Implementation Details

### 1. Confidence Scoring Approach

The implementation uses the **LLM Self-Reporting** approach, where we explicitly instruct the Box AI model to:
- Provide a confidence level for each extracted field
- Use a standardized scale of "High", "Medium", or "Low" confidence
- Return both the extracted value and confidence level in a structured format

### 2. Key Components Modified

#### 2.1 Metadata Extraction Module (`metadata_extraction.py`)

- **AI Agent Configuration**: Added system messages to both structured and freeform extraction methods that instruct the AI model to include confidence levels
- **Response Processing**: Added logic to parse the AI responses and extract both values and confidence levels
- **Data Structure**: Modified to store confidence levels alongside extracted values using `field_name_confidence` naming convention

```python
# Example of AI agent configuration with confidence instructions
ai_agent = {
    "type": "ai_agent_extract_structured",
    "long_text": {
        "model": ai_model,
        "mode": "default",
        "system_message": "You are an AI assistant specialized in extracting metadata from documents based on provided field definitions. For each field, analyze the document content and extract the corresponding value. CRITICALLY IMPORTANT: Respond for EACH field with a JSON object containing two keys: 1. \"value\": The extracted metadata value as a string. 2. \"confidence\": Your confidence level for this specific extraction, chosen from ONLY these three options: \"High\", \"Medium\", or \"Low\". Base your confidence on how certain you are about the extracted value given the document content and field definition. Example Response for a field: {\"value\": \"INV-12345\", \"confidence\": \"High\"}"
    },
    "basic_text": {
        "model": ai_model,
        "mode": "default",
        "system_message": "You are an AI assistant specialized in extracting metadata from documents based on provided field definitions. For each field, analyze the document content and extract the corresponding value. CRITICALLY IMPORTANT: Respond for EACH field with a JSON object containing two keys: 1. \"value\": The extracted metadata value as a string. 2. \"confidence\": Your confidence level for this specific extraction, chosen from ONLY these three options: \"High\", \"Medium\", or \"Low\". Base your confidence on how certain you are about the extracted value given the document content and field definition. Example Response for a field: {\"value\": \"INV-12345\", \"confidence\": \"High\"}"
    }
}
```

#### 2.2 Results Viewer Module (`results_viewer.py`)

- **Confidence Color Coding**: Added a function to assign colors based on confidence levels (High=green, Medium=orange, Low=red)
- **Confidence Filtering**: Added a multi-select filter to allow users to filter results by confidence level
- **Table View Enhancement**: Added confidence columns next to each field column with appropriate color coding
- **Detailed View Enhancement**: Added color-coded confidence indicators next to each field label

### 3. User Experience Improvements

- **Visual Indicators**: Color-coded confidence levels make it easy to identify fields with varying levels of confidence
- **Filtering Capability**: Users can filter results to focus on fields with specific confidence levels
- **Integrated Display**: Confidence information is seamlessly integrated into both table and detailed views

## How to Use

1. **Process Files**: The extraction process now automatically includes confidence scoring
2. **View Results**: Navigate to the "View Results" page to see extracted metadata with confidence levels
3. **Filter by Confidence**: Use the "Filter by Confidence Level" dropdown to focus on specific confidence levels
4. **Review Detailed Information**: In the detailed view, each field displays its confidence level in color-coded format

## Technical Notes

- The confidence scoring is implemented using Box AI agent overrides, specifically the `system_message` parameter
- The implementation preserves all existing functionality while adding the confidence scoring feature
- Both structured (template-based) and freeform extraction methods support confidence scoring
- The solution is designed to gracefully handle cases where confidence information is not available

## Future Enhancements

Potential future improvements to the confidence scoring feature:

1. **Confidence Thresholds**: Allow users to set minimum confidence thresholds for automatic metadata application
2. **Confidence Aggregation**: Add overall document confidence scores based on individual field confidence
3. **Confidence Improvement Suggestions**: Provide recommendations for improving low-confidence extractions
4. **Confidence Trend Analysis**: Track confidence levels across documents to identify patterns

## Conclusion

The LLM self-reporting confidence implementation enhances the Box Metadata AI application by providing users with transparency into the AI's certainty about extracted metadata. This helps users make more informed decisions about whether to trust and apply the extracted metadata to their Box files.
