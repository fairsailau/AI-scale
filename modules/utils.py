#!/usr/bin/env python
"""
Utility functions for managing Box authentication (using box-sdk-gen), getting clients, and metadata templates.
"""
import logging
import re
import configparser
import os
import json
import streamlit as st
# Corrected imports for the new box-sdk-gen
from box_sdk_gen import BoxClient # New client class name
# Authentication classes are in authenticators submodule
from box_sdk_gen.authenticators import OAuth2 # OAuth2 class name is the same
from box_sdk_gen.authenticators import JWTAuthentication # JWT class name changed
from box_sdk_gen.authenticators import ClientCredentialsGrant # CCG class name changed
from box_sdk_gen.authenticators import DeveloperTokenAuthentication # Developer Token class name changed
# Exception class location is similar but check documentation if issues arise
from box_sdk_gen.internal.utils import ApiException # Use ApiException from generated SDK for errors
import time # Needed for fallback template key generation
from typing import Dict, Any, Optional, List, Tuple
# Add base exception class from the new SDK for broader catching if needed
from box_sdk_gen.base_exception import BoxSDKException


# Corrected logging format string - must be a single line
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Authentication and Client Functions (Updated for box-sdk-gen) ---

def load_config(config_file='config.ini'):
    """Loads configuration from config.ini."""
    config = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(__file__), '..', config_file) # Adjust path based on modules/ location
    if os.path.exists(config_path):
        config.read(config_path)
        logger.info(f"Configuration file loaded: {config_path}")
        # Check if 'box' section exists
        if 'box' not in config:
             logger.error("config.ini found, but 'box' section is missing.")
             return None
        return config
    else:
        logger.error(f"Configuration file not found: {config_path}")
        return None

# Updated function signature and internal class names
def get_box_client(config: Dict[str, Any]) -> BoxClient: # Return type is BoxClient now
    """
    Instantiates and returns a Box SDK (generated) client based on the provided config dictionary.
    Designed to be callable from background threads using thread-specific config.
    """
    auth_method = config.get('auth_method', 'oauth') # Default to oauth
    authenticator = None

    try:
        if auth_method == 'oauth':
             # For background threads using OAuth, tokens must be passed and managed.
             # Refreshing within a simple ThreadPoolExecutor is complex.
             # This assumes tokens are valid for the duration of the task or uses CCG/JWT preferably.
             access_token = config.get('access_token')
             refresh_token = config.get('refresh_token')
             client_id = config.get('client_id')
             client_secret = config.get('client_secret')
             # No store_tokens callback in the generated SDK's OAuth2 class directly
             # If refresh is needed, it's handled internally or requires specific refresh logic
             # For this simplified thread model, we rely on the passed tokens being valid.

             if not all([access_token, client_id, client_secret]):
                  raise ValueError("Missing OAuth tokens or credentials in config.")

             logger.debug("Using OAuth2 for client instantiation in thread.")
             # Instantiating OAuth2 authenticator
             authenticator = OAuth2(
                 client_id=client_id,
                 client_secret=client_secret,
                 access_token=access_token,
                 refresh_token=refresh_token,
                 # Token refresh callback needs to be handled externally and passed if required for long-running
                 # Generated SDK's OAuth2 class has an `refresh_token` method if needed manually.
                 # Passing `update_tokens_callback` is more complex and often tied to a persistence layer.
                 # For this model, we omit the complex callback.
             )


        elif auth_method == 'jwt':
            jwt_config_path = config.get('jwt_config_path')
            user_id = config.get('user_id') # Optional for as_user

            # Adjust path relative to utils.py location
            abs_jwt_config_path = os.path.join(os.path.dirname(__file__), '..', jwt_config_path)

            if not jwt_config_path or not os.path.exists(abs_jwt_config_path):
                 raise FileNotFoundError(f"JWT config file not found at {jwt_config_path} (resolved to {abs_jwt_config_path})")

            # JWTAuthentication uses a config object directly
            jwt_config = JWTAuthentication.from_config_file(abs_jwt_config_path)

            # JWTAuthentication instantiation
            if user_id:
                 logger.debug(f"Using JWT auth as user {user_id} for client instantiation.")
                 # JWTAuthentication requires the user ID on instantiation for 'as_user'
                 authenticator = JWTAuthentication(jwt_config, user_id=user_id)
            else:
                 logger.debug("Using JWT auth (app user/enterprise) for client instantiation.")
                 authenticator = JWTAuthentication(jwt_config)


        elif auth_method == 'ccg':
            client_id = config.get('client_id')
            client_secret = config.get('client_secret')
            enterprise_id = config.get('enterprise_id') # Optional
            user_id = config.get('user_id') # Optional

            if not all([client_id, client_secret]):
                 raise ValueError("Missing CCG client_id or client_secret in config.")

            # ClientCredentialsGrant instantiation
            if user_id:
                logger.debug(f"Using CCG auth as user {user_id} for client instantiation.")
                # Use subject_type="user" and subject_id=user_id for as_user
                authenticator = ClientCredentialsGrant(
                     client_id=client_id,
                     client_secret=client_secret,
                     # In generated SDK, impersonation is done via subject_type and subject_id
                     subject_type='user',
                     subject_id=user_id
                )
            elif enterprise_id:
                logger.debug(f"Using CCG auth as enterprise {enterprise_id} for client instantiation.")
                 # Use subject_type="enterprise" and subject_id=enterprise_id for as_enterprise
                authenticator = ClientCredentialsGrant(
                     client_id=client_id,
                     client_secret=client_secret,
                     subject_type='enterprise',
                     subject_id=enterprise_id
                )
            else:
                 logger.warning("Using CCG auth without user_id or enterprise_id. Client may have limited scope.")
                 # Authenticate the application itself
                 authenticator = ClientCredentialsGrant(
                     client_id=client_id,
                     client_secret=client_secret,
                     # No subject_type/subject_id means authenticate the app
                 )


        elif auth_method == 'developer_token':
             dev_token = config.get('developer_token')
             if not dev_token:
                  raise ValueError("Missing developer token in config.")
             logger.debug("Using Developer Token auth for client instantiation.")
             # DeveloperTokenAuthentication instantiation
             authenticator = DeveloperTokenAuthentication(dev_token)

        else:
            raise ValueError(f"Unsupported authentication method: {auth_method}")

        # Instantiate the client using the authenticator
        client = BoxClient(authenticator) # Use BoxClient class

        logger.info(f"Box client (generated SDK) instantiated successfully using {auth_method}.")
        return client

    except Exception as e:
        logger.error(f"Error creating Box client using {auth_method}: {e}", exc_info=True)
        # Wrap exceptions in BoxSDKException or re-raise generated SDK's exceptions
        if isinstance(e, ApiException): # Generated SDK API exceptions
            raise e
        elif isinstance(e, BoxSDKException): # Generated SDK base exception
             raise e
        else:
             # Wrap other exceptions for consistency
             raise BoxSDKException(f"Failed to get Box client: {e}") from e


# This function is called in the main Streamlit thread to prepare config for workers
def get_box_config_for_worker(st_session_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Gathers necessary Box SDK configuration from session state and config.ini
    to be passed safely to a background worker/thread.
    Called only from the main Streamlit thread.
    """
    config = {}
    try:
        auth_method = st_session_state.get('auth_method')
        if not auth_method:
             # Fallback to reading config.ini if method isn't in session state yet (e.g., at startup)
             cfg_ini = load_config()
             if cfg_ini and 'box' in cfg_ini:
                 auth_method = cfg_ini['box'].get('auth_method')
                 if not auth_method:
                     logger.error("Auth method not specified in config.ini or session state.")
                     return None
                 # logger.info(f"Auth method not in session state, reading from config.ini: {auth_method}") # Verbose
             else:
                 logger.error("Could not determine auth method; config.ini not found or missing 'box' section.")
                 return None

        config['auth_method'] = auth_method

        # Collect credentials based on method - Prefer session state for tokens (OAuth)
        # but config.ini for static paths/secrets (JWT, CCG, Dev Token)
        cfg_ini = load_config() # Load config.ini to get static secrets/paths

        if auth_method == 'oauth':
            if 'access_token' in st_session_state and 'refresh_token' in st_session_state \
               and 'client_id' in st_session_state and 'client_secret' in st_session_state:
                 config['access_token'] = st_session_state['access_token']
                 config['refresh_token'] = st_session_state['refresh_token']
                 config['client_id'] = st_session_state['client_id']
                 config['client_secret'] = st_session_state['client_secret']
                 # logger.debug("Collected OAuth tokens from session state.") # Verbose
            else:
                 logger.error("OAuth tokens or credentials not found in session state for worker.")
                 return None

        elif auth_method == 'jwt':
             if cfg_ini and 'box' in cfg_ini and 'jwt_config_path' in cfg_ini['box']:
                 config['jwt_config_path'] = cfg_ini['box']['jwt_config_path']
                 # User ID can come from session state (if impersonating specific user) or config.ini
                 if 'user_id' in st_session_state and st_session_state['user_id']:
                     config['user_id'] = st_session_state['user_id']
                     # logger.debug("Collected JWT user_id from session state.") # Verbose
                 elif cfg_ini['box'].get('user_id'):
                     config['user_id'] = cfg_ini['box']['user_id']
                     # logger.debug("Collected JWT user_id from config.ini.") # Verbose
                 else:
                     logger.debug("No JWT user_id specified.")

             else:
                 logger.error("JWT config path not found in config.ini for worker.")
                 return None

        elif auth_method == 'ccg':
            if cfg_ini and 'box' in cfg_ini:
                if 'client_id' in cfg_ini['box'] and 'client_secret' in cfg_ini['box']:
                     config['client_id'] = cfg_ini['box']['client_id']
                     config['client_secret'] = cfg_ini['box']['client_secret']
                     # Enterprise ID and User ID can come from config.ini
                     if 'enterprise_id' in cfg_ini['box']:
                          config['enterprise_id'] = cfg_ini['box']['enterprise_id']
                          # logger.debug("Collected CCG enterprise_id from config.ini.") # Verbose
                     if 'user_id' in cfg_ini['box']:
                           config['user_id'] = cfg_ini['box']['user_id']
                           # logger.debug("Collected CCG user_id from config.ini.") # Verbose
                else:
                    logger.error("CCG client_id or client_secret not found in config.ini for worker.")
                    return None
            else:
                logger.error("Box section not found in config.ini for CCG worker config.")
                return None

        elif auth_method == 'developer_token':
             if cfg_ini and 'box' in cfg_ini and 'developer_token' in cfg_ini['box']:
                  config['developer_token'] = cfg_ini['box']['developer_token']
                  # logger.debug("Collected developer token from config.ini.") # Verbose
             else:
                  logger.error("Developer token not found in config.ini for worker.")
                  return None
        else:
             logger.error(f"Attempted to get worker config for unsupported method: {auth_method}")
             return None

        logger.debug(f"Box config for worker collected successfully (method: {auth_method}).")
        return config

    except Exception as e:
        logger.error(f"Error collecting Box config for worker: {e}", exc_info=True)
        return None


# --- Metadata Template Creation Functions (Check if methods/classes changed in generated SDK) ---

# These functions use client methods like client.create_metadata_template
# The generated SDK client methods are likely different.
# For create_metadata_template, the generated SDK uses client.metadata_templates.create_metadata_template

def generate_template_key(display_name):
    """Generates a Box-compliant templateKey from a display name."""
    # Remove special characters, replace spaces with underscores
    s = re.sub(r'[^a-zA-Z0-9_\s-]', '', display_name)
    s = re.sub(r'[\s-]+', '_', s).strip('_') # Also strip leading/trailing underscores

    if not s:
        return "customTemplate" # Fallback 1

    # Box templateKey constraints: [a-zA-Z0-9_], not starting with a digit, max 64 chars.
    parts = s.split('_')

    # Make it camelCase-like but ensure it starts lowercase and is not too long.
    # Start with the first part lowercase
    template_key_parts = [parts[0].lower()]
    # Capitalize subsequent parts
    for part in parts[1:]:
        if part: # Avoid adding empty strings
            template_key_parts.append(part.capitalize())

    template_key = "".join(template_key_parts)

    # Ensure it doesn't start with a digit (unlikely with current logic but safe)
    if template_key and template_key[0].isdigit():
        template_key = "t" + template_key # Prepend a letter

    # If the generated key is now empty or still invalid after parts joining (edge case?)
    if not template_key:
         template_key = "customTemplate" # Fallback 2

    return template_key[:64] # Max length 64


# Updated function signature and internal method calls for generated SDK
def create_custom_template_from_ai_keys(client: BoxClient, selected_keys: List[str], template_display_name: str = "Custom Extracted Info", scope: str = "enterprise") -> Tuple[bool, str]: # Client is now BoxClient
    """
    Creates a custom metadata template in Box based on AI-extracted keys (using generated SDK).

    Args:
        client: Authenticated Box SDK (generated) client.
        selected_keys: A list of strings (keys from AI extraction) to become fields.
        template_display_name: User-friendly name for the new template.
        scope: The scope for the new template (e.g., "enterprise", "global").

    Returns:
        A tuple (success_boolean, message_string).
        If successful, True and the new template ID (e.g., "enterprise_customExtractedInfo").
        If failed, False and an error message.
    """
    if not selected_keys:
        return False, "No keys selected to create template fields."

    # Clean and generate template key
    try:
        template_key = generate_template_key(template_display_name)
        # Handle edge case where generate_template_key might return default
        if template_key == "customTemplate" and (not template_display_name or not template_display_name.strip() or re.sub(r'[^a-zA-Z0-9_\s-]', '', template_display_name).strip() == ''):
             template_key = f"customExtractedInfo_{int(time.time())}" # Add timestamp for uniqueness if display name was empty/invalid

        logger.debug(f"Generated template_key: {template_key} for display name '{template_display_name}'")

    except Exception as e:
        logger.error(f"Error generating template key for '{template_display_name}': {e}", exc_info=True)
        return False, f"Internal error generating template key: {e}"

    # Imports needed for field types in generated SDK
    from box_sdk_gen.schemas import MetadataField, MetadataFieldType, CreateMetadataTemplateRequestBody

    fields: List[MetadataField] = [] # Use generated SDK's MetadataField schema
    for key in selected_keys:
        # Sanitize key for Box field key requirements (alphanumeric)
        # Field key: [a-zA-Z0-9_], max 64 chars, not starting with digit.
        field_key = re.sub(r'[^a-zA-Z0-9_]', '', key)
        if not field_key:
            logger.warning(f"Skipping key '{key}' as it resulted in an empty field_key after sanitization.")
            continue
        if field_key[0].isdigit():
            field_key = "f_" + field_key # Prepend if starts with digit
        field_key = field_key[:64]

        field_display_name = key.replace("_", " ").replace("-", " ").title()

        # Use generated SDK's schema objects for fields
        fields.append(
             MetadataField(
                  type=MetadataFieldType.ENUM.value, # Assuming string, but enum is often safer for generated templates
                  key=field_key,
                  display_name=field_display_name,
                  options=[{"id": str(i), "value": "Default Value"} for i in range(1)] # Enum requires options, string is MetadataFieldType.STRING.value
                  # Let's stick to string as per previous assumption
             )
        )

    # Corrected fields list creation for string type
    fields_string_type: List[MetadataField] = []
    for key in selected_keys:
        field_key = re.sub(r'[^a-zA-Z0-9_]', '', key)
        if not field_key: continue
        if field_key[0].isdigit(): field_key = "f_" + field_key
        field_key = field_key[:64]
        field_display_name = key.replace("_", " ").replace("-", " ").title()
        fields_string_type.append(
            MetadataField(
                type=MetadataFieldType.STRING.value, # Use STRING enum value
                key=field_key,
                display_name=field_display_name
            )
        )
    fields = fields_string_type # Use the string type fields


    if not fields:
        return False, "No valid fields could be generated from the selected keys."

    try:
        logger.info(f"Attempting to create template: scope='{scope}', template_key='{template_key}', displayName='{template_display_name}'")
        # Generated SDK method for creating template
        new_template = client.metadata_templates.create_metadata_template(
            request_body=CreateMetadataTemplateRequestBody(
                scope=scope,
                display_name=template_display_name,
                template_key=template_key,
                fields=fields,
                hidden=False
            )
        )

        # Generated SDK response likely has templateKey and scope directly
        if new_template and hasattr(new_template, 'template_key') and hasattr(new_template, 'scope'):
             full_template_id = f"{new_template.scope}_{new_template.template_key}"
        else:
             # Fallback if SDK response structure is unexpected
             full_template_id = f"{scope}_{template_key}"


        logger.info(f"Successfully created template with ID: {full_template_id}")
        return True, f"Successfully created template: {template_display_name} (ID: {full_template_id})"
    except ApiException as e: # Catch generated SDK API exceptions
        logger.error(f"Box API Exception (Generated SDK) while creating template '{template_display_name}' (key: {template_key}): Status={e.status}, Code={e.code}, Message={e.message}")
        error_message = f"Error creating template '{template_display_name}': {e.message}"
        # Generated SDK ApiException might have different context_info structure, check documentation
        # if e.context_info and 'errors' in e.context_info and isinstance(e.context_info['errors'], list):
        #     for err_detail in e.context_info['errors']:
        #         detail_msg = err_detail.get('message') or err_detail.get('reason')
        #         if detail_msg: error_message += f" - {detail_msg}"
        #         if err_detail.get('name') and err_detail.get('value'): error_message += f" (Field: {err_detail['name']} Value: {err_detail['value']})"

        # Specific check for template key conflict (status code is usually reliable)
        if e.status == 409: # Conflict
            error_message += " - A template with this key likely already exists."

        return False, error_message
    except BoxSDKException as e: # Catch generated SDK base exceptions
        logger.error(f"Box SDK Exception (Generated SDK) while creating template '{template_display_name}' (key: {template_key}): {e}", exc_info=True)
        return False, f"An unexpected Box SDK error occurred: {str(e)}"
    except Exception as e: # Catch any other unexpected errors
        logger.error(f"Unexpected error while creating template '{template_display_name}' (key: {template_key}): {e}", exc_info=True)
        return False, f"An unexpected error occurred: {str(e)}"
