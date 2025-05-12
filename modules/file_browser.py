import streamlit as st
from typing import List, Dict, Any

def file_browser():
    """
    Browse and select Box files/folders for processing
    """
    st.title('Box File Browser')
    if not st.session_state.authenticated or not st.session_state.client:
        st.error('Please authenticate with Box first')
        return
    st.write('Browse your Box files and select items for metadata extraction.')
    if 'current_folder_id' not in st.session_state:
        st.session_state.current_folder_id = '0'
    if 'folder_path' not in st.session_state:
        st.session_state.folder_path = [{'id': '0', 'name': 'All Files'}]
    if 'selected_files' not in st.session_state:
        st.session_state.selected_files = []

    def navigate_to_folder(folder_id: str, folder_name: str):
        for i, folder in enumerate(st.session_state.folder_path):
            if folder['id'] == folder_id:
                st.session_state.folder_path = st.session_state.folder_path[:i + 1]
                break
        else:
            st.session_state.folder_path.append({'id': folder_id, 'name': folder_name})
        st.session_state.current_folder_id = folder_id
        st.rerun()

    def toggle_file_selection(file_id: str, file_name: str, file_type: str):
        for i, file in enumerate(st.session_state.selected_files):
            if file['id'] == file_id:
                st.session_state.selected_files.pop(i)
                return
        st.session_state.selected_files.append({'id': file_id, 'name': file_name, 'type': file_type})
    st.write('#### Location')
    breadcrumb_cols = st.columns(len(st.session_state.folder_path))
    for i, folder in enumerate(st.session_state.folder_path):
        with breadcrumb_cols[i]:
            if st.button(folder['name'], key=f"breadcrumb_{folder['id']}"):
                navigate_to_folder(folder['id'], folder['name'])
    try:
        current_folder = st.session_state.client.folder(folder_id=st.session_state.current_folder_id).get()
        items = st.session_state.client.folder(folder_id=st.session_state.current_folder_id).get_items()
        folders = []
        files = []
        for item in items:
            if item.type == 'folder':
                folders.append(item)
            elif item.type == 'file':
                files.append(item)
        if folders:
            st.write('#### Folders')
            folder_cols = st.columns(3)
            for i, folder in enumerate(folders):
                with folder_cols[i % 3]:
                    if st.button(f'📁 {folder.name}', key=f'folder_{folder.id}'):
                        navigate_to_folder(folder.id, folder.name)
        if files:
            st.write('#### Files')
            st.write('Filter files:')
            col1, col2 = st.columns(2)
            with col1:
                search_term = st.text_input('Search by name', key='file_search')
            with col2:
                file_types = st.multiselect('Filter by type', options=['pdf', 'docx', 'xlsx', 'pptx', 'txt', 'csv', 'json'], default=[], key='file_type_filter')
            filtered_files = files
            if search_term:
                filtered_files = [f for f in filtered_files if search_term.lower() in f.name.lower()]
            if file_types:
                filtered_files = [f for f in filtered_files if f.name.split('.')[-1].lower() in file_types]
            for file in filtered_files:
                file_type = file.name.split('.')[-1] if '.' in file.name else 'unknown'
                is_selected = any((selected['id'] == file.id for selected in st.session_state.selected_files))
                col1, col2, col3 = st.columns([0.1, 0.7, 0.2])
                with col1:
                    if st.checkbox('', value=is_selected, key=f'select_{file.id}'):
                        if not is_selected:
                            toggle_file_selection(file.id, file.name, file_type)
                    elif is_selected:
                        toggle_file_selection(file.id, file.name, file_type)
                with col2:
                    st.write(f'**{file.name}**')
                with col3:
                    st.write(f'Type: {file_type}')
        else:
            st.info('No files in this folder')
    except Exception as e:
        st.error(f'Error loading folder contents: {str(e)}')
    st.write('---')
    st.write('### Selected Files')
    if st.session_state.selected_files:
        for i, file in enumerate(st.session_state.selected_files):
            col1, col2, col3 = st.columns([0.1, 0.7, 0.2])
            with col1:
                if st.button('❌', key=f"remove_{file['id']}"):
                    st.session_state.selected_files.pop(i)
                    st.rerun()
            with col2:
                st.write(f"**{file['name']}**")
            with col3:
                st.write(f"Type: {file['type']}")
        if st.button('Clear Selection'):
            st.session_state.selected_files = []
            st.rerun()
    else:
        st.info('No files selected. Browse and select files for metadata extraction.')
    if st.session_state.selected_files:
        if st.button('Continue to Metadata Configuration', use_container_width=True):
            st.session_state.current_page = 'Metadata Configuration'
            st.rerun()