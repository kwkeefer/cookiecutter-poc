"""HTML parsing utility for extracting data from web responses.

**End-to-End Example:**

.. code-block:: python

    import requests
    from your_project.utils.html_parser import HTMLParser
    from your_project.utils.output import out

    # Make a request to target
    response = requests.get("http://target.com/login")

    # Parse the HTML response
    parser = HTMLParser.from_response(response)

    # Find CSRF token for form submission
    csrf_token = parser.find_csrf_token()
    if csrf_token:
        out.success(f"Found CSRF token: {csrf_token}")

    # Find and extract login form data
    forms = parser.find_forms()
    if forms:
        login_form = forms[0]  # First form on page
        form_data = parser.extract_form_data(login_form)

        # Update with our credentials
        form_data['username'] = 'admin'
        form_data['password'] = 'password'
        form_data['csrf_token'] = csrf_token  # Include CSRF token

        # Get form action URL
        action = login_form.get('action', '/login')
        method = login_form.get('method', 'POST')

        # Submit the form
        if method.upper() == 'POST':
            resp = requests.post(f"http://target.com{action}", data=form_data)
        else:
            resp = requests.get(f"http://target.com{action}", params=form_data)

    # Search for specific elements
    error_msg = parser.find_by_class('error-message')
    if error_msg:
        out.error(f"Login failed: {error_msg.text}")

    # Extract all links for crawling
    links = parser.find_links()
    for link in links:
        href = link.get('href')
        if href and href.startswith('/admin'):
            out.info(f"Found admin link: {href}")
"""

from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional, Union
from .output import out


class HTMLParser:
    def __init__(self, html: str):
        self.soup = BeautifulSoup(html, 'html.parser')
        self.html = html

    @classmethod
    def from_response(cls, response):
        """Create parser from requests Response object.

        Args:
            response: A requests.Response object

        Returns:
            HTMLParser instance initialized with response text
        """
        return cls(response.text)

    @classmethod
    def from_file(cls, filepath: str):
        """Create parser from HTML file.

        Args:
            filepath: Path to HTML file

        Returns:
            HTMLParser instance initialized with file contents
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            return cls(f.read())

    def find_by_id(self, element_id: str):
        """Find first element with given ID.

        Args:
            element_id: The ID attribute value to search for

        Returns:
            BeautifulSoup Tag object or None
        """
        return self.soup.find(id=element_id)

    def find_all_by_id(self, element_id: str):
        """Find all elements with given ID (invalid HTML but sometimes happens).

        Args:
            element_id: The ID attribute value to search for

        Returns:
            List of BeautifulSoup Tag objects
        """
        return self.soup.find_all(id=element_id)

    def find_by_class(self, class_name: str):
        """Find first element with given class name.

        Args:
            class_name: The CSS class to search for

        Returns:
            BeautifulSoup Tag object or None
        """
        return self.soup.find(class_=class_name)

    def find_all_by_class(self, class_name: str):
        """Find all elements with given class name.

        Args:
            class_name: The CSS class to search for

        Returns:
            List of BeautifulSoup Tag objects
        """
        return self.soup.find_all(class_=class_name)

    def find_by_tag(self, tag_name: str):
        return self.soup.find(tag_name)

    def find_all_by_tag(self, tag_name: str):
        return self.soup.find_all(tag_name)

    def find_by_name(self, name: str):
        return self.soup.find(attrs={'name': name})

    def find_all_by_name(self, name: str):
        return self.soup.find_all(attrs={'name': name})

    def find_by_attr(self, attr_name: str, attr_value: str):
        return self.soup.find(attrs={attr_name: attr_value})

    def find_all_by_attr(self, attr_name: str, attr_value: str):
        return self.soup.find_all(attrs={attr_name: attr_value})

    def find_forms(self) -> List:
        """Find all form elements in the HTML.

        Returns:
            List of form Tag objects
        """
        return self.soup.find_all('form')

    def find_inputs(self, form=None) -> List:
        """Find all input elements, optionally within a specific form.

        Args:
            form: Optional form element to search within

        Returns:
            List of input Tag objects
        """
        search_in = form if form else self.soup
        return search_in.find_all('input')

    def find_links(self) -> List:
        """Find all links (anchor tags with href).

        Returns:
            List of anchor Tag objects with href attributes
        """
        return self.soup.find_all('a', href=True)

    def find_scripts(self) -> List:
        return self.soup.find_all('script')

    def find_meta(self) -> List:
        return self.soup.find_all('meta')

    def extract_text(self, element=None) -> str:
        target = element if element else self.soup
        return target.get_text(strip=True)

    def extract_attrs(self, element) -> Dict:
        if hasattr(element, 'attrs'):
            return dict(element.attrs)
        return {}

    def extract_form_data(self, form) -> Dict[str, Any]:
        """Extract all input data from a form element.

        Extracts names and values from input, textarea, and select elements,
        handling checkboxes, radio buttons, and default values properly.

        Args:
            form: BeautifulSoup form Tag object

        Returns:
            Dict mapping input names to their values

        Example:
            .. code-block:: python

                form = parser.find_forms()[0]
                data = parser.extract_form_data(form)
                data['username'] = 'admin'  # Update with your values
                requests.post(url, data=data)
        """
        data = {}
        inputs = form.find_all(['input', 'textarea', 'select'])

        for inp in inputs:
            name = inp.get('name')
            if not name:
                continue

            if inp.name == 'input':
                if inp.get('type') == 'checkbox':
                    if inp.get('checked'):
                        data[name] = inp.get('value', 'on')
                elif inp.get('type') == 'radio':
                    if inp.get('checked'):
                        data[name] = inp.get('value')
                else:
                    data[name] = inp.get('value', '')
            elif inp.name == 'textarea':
                data[name] = inp.text
            elif inp.name == 'select':
                option = inp.find('option', selected=True)
                if option:
                    data[name] = option.get('value', option.text)
                else:
                    first_option = inp.find('option')
                    if first_option:
                        data[name] = first_option.get('value', first_option.text)

        return data

    def search(self, text: str, tag: Optional[str] = None):
        import re
        if tag:
            return self.soup.find_all(tag, string=re.compile(text, re.I))
        else:
            return self.soup.find_all(string=re.compile(text, re.I))

    def css_select(self, selector: str):
        """Select elements using CSS selector syntax.

        Args:
            selector: CSS selector string (e.g., 'div.class', '#id', 'form input[type="hidden"]')

        Returns:
            List of matching Tag objects

        Example:
            .. code-block:: python

                # Find all hidden inputs
                hidden = parser.css_select('input[type="hidden"]')

                # Find all links in navigation
                nav_links = parser.css_select('nav a')
        """
        return self.soup.select(selector)

    def css_select_one(self, selector: str):
        """Select first element matching CSS selector.

        Args:
            selector: CSS selector string

        Returns:
            First matching Tag object or None
        """
        return self.soup.select_one(selector)

    def get_title(self) -> Optional[str]:
        title = self.soup.find('title')
        return title.text if title else None

    def get_headers(self) -> Dict[str, List[str]]:
        headers = {}
        for i in range(1, 7):
            h_tags = self.soup.find_all(f'h{i}')
            if h_tags:
                headers[f'h{i}'] = [h.get_text(strip=True) for h in h_tags]
        return headers

    def find_csrf_token(self) -> Optional[str]:
        """Find CSRF token in the HTML (checks common locations and names).

        Searches for CSRF tokens in:
        - Meta tags with common CSRF names
        - Input fields with common CSRF names
        - Hidden input fields containing 'csrf' or 'token'

        Returns:
            CSRF token value if found, None otherwise

        Example:
            .. code-block:: python

                parser = HTMLParser.from_response(response)
                csrf = parser.find_csrf_token()
                if csrf:
                    form_data = {'csrf_token': csrf, 'username': 'admin'}
                    requests.post(url, data=form_data)
        """
        common_names = [
            'csrf_token', 'csrftoken', 'csrf', '_csrf', 'authenticity_token',
            'csrfmiddlewaretoken', '__RequestVerificationToken', 'token',
            '_token', 'csrf-token', 'CSRF-TOKEN', 'X-CSRF-Token'
        ]

        # Check meta tags
        for name in common_names:
            meta = self.soup.find('meta', attrs={'name': name})
            if meta and meta.get('content'):
                return meta.get('content')

        # Check input fields
        for name in common_names:
            input_field = self.soup.find('input', attrs={'name': name})
            if input_field and input_field.get('value'):
                return input_field.get('value')

        # Check hidden inputs (broader search)
        hidden_inputs = self.soup.find_all('input', attrs={'type': 'hidden'})
        for inp in hidden_inputs:
            name = inp.get('name', '').lower()
            if 'csrf' in name or 'token' in name:
                return inp.get('value')

        return None

    def find_all_csrf_tokens(self) -> Dict[str, str]:
        tokens = {}

        # Meta tags
        meta_tags = self.soup.find_all('meta')
        for meta in meta_tags:
            name = meta.get('name', '').lower()
            if 'csrf' in name or 'token' in name:
                content = meta.get('content')
                if content:
                    tokens[f"meta[{meta.get('name')}]"] = content

        # Input fields
        inputs = self.soup.find_all('input')
        for inp in inputs:
            name = inp.get('name', '').lower()
            if 'csrf' in name or 'token' in name:
                value = inp.get('value')
                if value:
                    tokens[f"input[{inp.get('name')}]"] = value

        return tokens

    def dump_forms(self):
        """Print all forms with their inputs and values (for debugging).

        Useful for quick reconnaissance of form structures and hidden fields.

        Example:
            .. code-block:: python

                # Quick form analysis
                parser = HTMLParser.from_response(response)
                parser.dump_forms()
                # Output:
                # Form 1:
                #   Action: /login
                #   Method: POST
                #   username:
                #   password:
                #   csrf_token: abc123...
        """
        forms = self.find_forms()
        for i, form in enumerate(forms):
            out.info(f"Form {i+1}:")
            print(f"  Action: {form.get('action', 'N/A')}")
            print(f"  Method: {form.get('method', 'GET')}")
            data = self.extract_form_data(form)
            for name, value in data.items():
                print(f"  {name}: {value}")
            print()

    def dump_links(self):
        """Print all links found in the HTML (for crawling/mapping).

        Example:
            .. code-block:: python

                parser.dump_links()
                # Output:
                # Home: /
                # Admin Panel: /admin
                # Login: /login
        """
        links = self.find_links()
        for link in links:
            text = link.get_text(strip=True)
            href = link.get('href')
            if text:
                print(f"{text}: {href}")
            else:
                print(href)


def quick_parse(html: str) -> HTMLParser:
    """Quick helper to create parser from HTML string.

    Args:
        html: HTML content as string

    Returns:
        HTMLParser instance
    """
    return HTMLParser(html)


def parse_response(response) -> HTMLParser:
    """Quick helper to create parser from requests Response.

    Args:
        response: requests.Response object

    Returns:
        HTMLParser instance

    Example:
        .. code-block:: python

            resp = requests.get("http://target.com")
            parser = parse_response(resp)
            csrf = parser.find_csrf_token()
    """
    return HTMLParser.from_response(response)


def parse_file(filepath: str) -> HTMLParser:
    """Quick helper to create parser from HTML file.

    Args:
        filepath: Path to HTML file

    Returns:
        HTMLParser instance
    """
    return HTMLParser.from_file(filepath)