import bleach

ALLOWED_TAGS = [ # allowed html tags specified
    'b', 'i', 'u', 'em', 'strong',
    'a', 'p', 'ul', 'ol', 'li'
]
 # sanitises input from username and password
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title']
}

ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']

def sanitize_html(text): # callable on raw data
    return bleach.clean( # bleaches
        text,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True
    )