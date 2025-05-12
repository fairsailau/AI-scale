import streamlit as st
from boxsdk import OAuth2, Client, JWTAuth
import os
import json
import webbrowser
from urllib.parse import parse_qs, urlparse
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_secrets_available(required_sections):
    """Checks if required sections/keys exist in st.secrets."""
    missing = []
    if not hasattr(st.secrets, 'get'):
        st.error('Streamlit Secrets not available. Ensure secrets are configured.')
        return (False, ['Streamlit Secrets configuration'])
    for section in required_sections:
        if isinstance(section, str):
            if not st.secrets.get(section):
                missing.append(section)
        elif isinstance(section, dict):
            section_name = list(section.keys())[0]
            keys = section[section_name]
            if not st.secrets.get(section_name):
                missing.append(f"Section '{section_name}'")
            else:
                for key in keys:
                    parts = key.split('.')
                    current_level = st.secrets.get(section_name)
                    key_found = True
                    for part in parts:
                        is_dict_like = hasattr(current_level, '__getitem__') and hasattr(current_level, 'get')
                        if is_dict_like and current_level.get(part) is not None:
                            current_level = current_level[part]
                        else:
                            missing.append(f"'{section_name}.{key}'")
                            key_found = False
                            break
    if missing:
        st.error(f"Missing required secrets: {', '.join(missing)}. Please configure them in Streamlit Cloud App settings -> Secrets.")
        return (False, missing)
    return (True, [])

def authenticate():
    """
    Handle Box authentication using OAuth2 or JWT (credentials from st.secrets)
    """
    st.title('Box Authentication')
    if st.session_state.get('authenticated') and st.session_state.get('client'):
        st.success(f'You are already authenticated as {st.session_state.user.name}!')
        if st.button('Logout', key='auth_logout_btn'):
            st.session_state.authenticated = False
            st.session_state.client = None
            st.session_state.user = None
            st.session_state.pop('auth_credentials', None)
            st.rerun()
        return
    st.write('\n    ## Connect to Box\n\n    This app requires authentication with Box using credentials configured in Streamlit Secrets.\n    Select the authentication method configured in your secrets.\n    ')
    auth_method = st.radio('Select authentication method (must match your Streamlit Secrets configuration):', options=['OAuth 2.0', 'JWT', 'Developer Token (Testing Only)'], index=2, key='auth_method_secrets_radio', help='Choose the method corresponding to the secrets you have configured.')
    if auth_method == 'OAuth 2.0':
        oauth2_authentication_secrets()
    elif auth_method == 'JWT':
        jwt_authentication_secrets()
    else:
        developer_token_authentication_secrets()
    with st.expander('How to configure Streamlit Secrets for Box Authentication'):
        st.write('\n        Go to your Streamlit Cloud App settings -> Secrets and add the following in TOML format, depending on your chosen authentication method:\n\n        **1. OAuth 2.0:**\n        ```toml\n        [box_oauth]\n        client_id = "YOUR_OAUTH_CLIENT_ID"\n        client_secret = "YOUR_OAUTH_CLIENT_SECRET"\n        # Optional: Specify redirect URI if different from default\n        # redirect_uri = "YOUR_REDIRECT_URI" \n        ```\n        *Note: The default Redirect URI used by the app if not specified here is `http://localhost:8501/`. Ensure this matches your Box App configuration.* \n\n        **2. JWT:**\n        Copy the *entire contents* of your `config.json` file downloaded from the Box Developer Console and paste it under the `[box_jwt]` section. It should look something like this:\n        ```toml\n        [box_jwt]\n        boxAppSettings = { clientID = "YOUR_JWT_CLIENT_ID", clientSecret = "YOUR_JWT_CLIENT_SECRET", appAuth = { publicKeyID = "YOUR_PUBLIC_KEY_ID", privateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nYOUR_ENCRYPTED_PRIVATE_KEY\n-----END ENCRYPTED PRIVATE KEY-----", passphrase = "YOUR_PASSPHRASE" } }\n        enterpriseID = "YOUR_ENTERPRISE_ID"\n        ```\n        *Make sure the `privateKey` includes the `-----BEGIN...` and `-----END...` lines and all newline characters (`\n`). You might need to format it carefully.* \n\n        **3. Developer Token (Testing Only):**\n        ```toml\n        [box_dev]\n        client_id = "YOUR_DEV_APP_CLIENT_ID" # Often same as OAuth\n        client_secret = "YOUR_DEV_APP_CLIENT_SECRET" # Often same as OAuth\n        developer_token = "YOUR_DEVELOPER_TOKEN"\n        ```\n        *Remember: Developer tokens expire after 60 minutes.* \n        ')

def oauth2_authentication_secrets():
    """
    Implement OAuth 2.0 authentication flow using credentials from st.secrets
    """
    st.subheader('OAuth 2.0 Authentication (using Streamlit Secrets)')
    secrets_ok, _ = check_secrets_available([{'box_oauth': ['client_id', 'client_secret']}])
    if not secrets_ok:
        return
    client_id = st.secrets['box_oauth']['client_id']
    client_secret = st.secrets['box_oauth']['client_secret']
    redirect_uri = st.secrets.get('box_oauth', {}).get('redirect_uri', 'http://localhost:8501/')
    try:
        oauth = OAuth2(client_id=client_id, client_secret=client_secret, store_tokens=store_tokens)
        auth_url, csrf_token = oauth.get_authorization_url(redirect_uri)
        st.session_state.csrf_token = csrf_token
        st.session_state.oauth = oauth
        st.write('Please authorize the app by clicking the link below:')
        st.markdown(f'[Authorize App]({auth_url})')
        if st.button('Open Authorization Link in New Tab'):
            webbrowser.open(auth_url)
        st.write(f"After authorization, you will be redirected (likely to `{redirect_uri}`). Copy the **full URL** from your browser's address bar and paste it below:")
        auth_code_url = st.text_input('Paste the full Redirect URL here')
        if auth_code_url:
            try:
                parsed_url = urlparse(auth_code_url)
                query_params = parse_qs(parsed_url.query)
                if 'code' in query_params:
                    auth_code = query_params['code'][0]
                    state = query_params.get('state', [None])[0]
                    if not state or state != st.session_state.get('csrf_token'):
                        st.error('CSRF token mismatch. Authentication failed. Please try again.')
                        logger.error('CSRF token mismatch during OAuth callback.')
                        return
                    with st.spinner('Authenticating...'):
                        access_token, refresh_token = oauth.authenticate(auth_code)
                        client = Client(oauth)
                        current_user = client.user().get()
                        st.session_state.authenticated = True
                        st.session_state.client = client
                        st.session_state.user = current_user
                        logger.info(f'OAuth: Successfully authenticated as {current_user.name}')
                        st.success(f'Successfully authenticated as {current_user.name}!')
                        st.rerun()
                else:
                    st.error("Could not find authorization code ('...&code=...') in the pasted URL. Please ensure you paste the full URL after redirection.")
            except Exception as e:
                st.error(f'Error processing authorization code: {str(e)}')
                logger.exception('Error processing OAuth authorization code:')
    except Exception as e:
        st.error(f'OAuth initialization failed: {str(e)}')
        logger.exception('OAuth initialization failed:')

def jwt_authentication_secrets():
    """
    Implement JWT authentication flow using config from st.secrets
    """
    st.subheader('JWT Authentication (using Streamlit Secrets)')
    secrets_ok, _ = check_secrets_available(['box_jwt'])
    if not secrets_ok:
        return
    config_dict = st.secrets['box_jwt']
    config_dict_plain = config_dict.to_dict() if hasattr(config_dict, 'to_dict') else config_dict
    if not isinstance(config_dict_plain, dict) or 'boxAppSettings' not in config_dict_plain or 'enterpriseID' not in config_dict_plain:
        st.error('The `[box_jwt]` section in your Streamlit Secrets does not seem to have the correct structure. Please ensure it mirrors the Box `config.json` format.')
        logger.error('box_jwt secret does not have the expected structure.')
        return
    if st.button('Authenticate using JWT Secrets'):
        try:
            with st.spinner('Authenticating using JWT...'):
                auth = JWTAuth.from_settings_dictionary(config_dict_plain)
                client = Client(auth)
                service_account = client.user().get()
                st.session_state.authenticated = True
                st.session_state.client = client
                st.session_state.user = service_account
                if 'auth_credentials' not in st.session_state:
                    st.session_state.auth_credentials = {}
                st.session_state.auth_credentials['jwt_config'] = config_dict_plain
                logger.info(f'JWT: Successfully authenticated as {service_account.name} (Service Account)')
                st.success(f'Successfully authenticated as {service_account.name} (Service Account)!')
                st.rerun()
        except Exception as e:
            st.error(f'JWT Authentication failed: {str(e)}')
            logger.exception('JWT Authentication failed:')

def developer_token_authentication_secrets():
    """
    Implement developer token authentication using token from st.secrets
    """
    st.subheader('Developer Token Authentication (using Streamlit Secrets)')
    st.warning('Developer tokens expire after 60 minutes and are for testing only.')
    #st.write('DEBUG: Checking st.secrets.box_dev:', st.secrets.get('box_dev'))
    secrets_ok, _ = check_secrets_available([{'box_dev': ['client_id', 'client_secret', 'developer_token']}])
    if not secrets_ok:
        return
    box_dev_secrets = st.secrets['box_dev']
    client_id = box_dev_secrets['client_id']
    client_secret = box_dev_secrets['client_secret']
    developer_token = box_dev_secrets['developer_token']
    if st.button('Authenticate using Developer Token Secret'):
        try:
            with st.spinner('Authenticating using Developer Token...'):
                auth = OAuth2(client_id=client_id, client_secret=client_secret, access_token=developer_token, store_tokens=store_tokens)
                client = Client(auth)
                current_user = client.user().get()
                st.session_state.authenticated = True
                st.session_state.client = client
                st.session_state.user = current_user
                if 'auth_credentials' not in st.session_state:
                    st.session_state.auth_credentials = {}
                st.session_state.auth_credentials['client_id'] = client_id
                st.session_state.auth_credentials['client_secret'] = client_secret
                st.session_state.auth_credentials['access_token'] = developer_token
                logger.info(f'Dev Token: Successfully authenticated as {current_user.name}')
                st.success(f'Successfully authenticated as {current_user.name}!')
                st.rerun()
        except Exception as e:
            st.error(f'Developer Token Authentication failed: {str(e)}')
            logger.exception('Developer Token Authentication failed:')

def store_tokens(access_token, refresh_token=None):
    """
    Store tokens in session state (used primarily by OAuth flow).
    Also stores credentials needed for potential refresh.
    """
    logger.info('Storing authentication tokens in session state (store_tokens callback)')
    st.session_state.access_token = access_token
    if refresh_token:
        st.session_state.refresh_token = refresh_token
    if 'auth_credentials' not in st.session_state:
        st.session_state.auth_credentials = {}
    try:
        if st.secrets.get('box_oauth'):
            st.session_state.auth_credentials['client_id'] = st.secrets['box_oauth']['client_id']
            st.session_state.auth_credentials['client_secret'] = st.secrets['box_oauth']['client_secret']
            logger.info('Captured client_id/secret from secrets for token refresh storage.')
        elif st.secrets.get('box_dev'):
            st.session_state.auth_credentials['client_id'] = st.secrets['box_dev']['client_id']
            st.session_state.auth_credentials['client_secret'] = st.secrets['box_dev']['client_secret']
            logger.info('Captured client_id/secret from dev token secrets for token refresh storage.')
    except Exception as e:
        logger.warning(f'Could not store client_id/secret for potential token refresh: {e}')
