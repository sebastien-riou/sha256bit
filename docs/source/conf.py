# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'sha256bit'
copyright = '2023, Sebastien Riou'
author = 'Sebastien Riou'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration


extensions = [
    'sphinx_rtd_theme',
    'sphinx_multiversion',
]

smv_tag_whitelist = r'^v\d+\.\d+.*$|latest'  # all tags of form v*.*.x and latest
# Whitelist pattern for branches (set to '' to ignore all branches)
smv_branch_whitelist = ''
smv_released_pattern = r'v.*'
smv_latest_version = 'v0.1'
smv_remote_whitelist = None


templates_path = ['_templates']
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']
