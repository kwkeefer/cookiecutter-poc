from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional, Union
from .output import out


class HTMLParser:
    def __init__(self, html: str):
        self.soup = BeautifulSoup(html, 'html.parser')
        self.html = html

    @classmethod
    def from_response(cls, response):
        return cls(response.text)

    @classmethod
    def from_file(cls, filepath: str):
        with open(filepath, 'r', encoding='utf-8') as f:
            return cls(f.read())

    def find_by_id(self, element_id: str):
        return self.soup.find(id=element_id)

    def find_all_by_id(self, element_id: str):
        return self.soup.find_all(id=element_id)

    def find_by_class(self, class_name: str):
        return self.soup.find(class_=class_name)

    def find_all_by_class(self, class_name: str):
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
        return self.soup.find_all('form')

    def find_inputs(self, form=None) -> List:
        search_in = form if form else self.soup
        return search_in.find_all('input')

    def find_links(self) -> List:
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
        return self.soup.select(selector)

    def css_select_one(self, selector: str):
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
        links = self.find_links()
        for link in links:
            text = link.get_text(strip=True)
            href = link.get('href')
            if text:
                print(f"{text}: {href}")
            else:
                print(href)


def quick_parse(html: str) -> HTMLParser:
    return HTMLParser(html)


def parse_response(response) -> HTMLParser:
    return HTMLParser.from_response(response)


def parse_file(filepath: str) -> HTMLParser:
    return HTMLParser.from_file(filepath)