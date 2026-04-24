from setuptools import setup, find_packages

setup(
    name='WebVulnScanner',
    version='1.0.0',
    description='Open-source web vulnerability scanner with multi-layer detection and intelligent reporting',
    author='moadh704',
    py_modules=['main', 'config'],
    packages=find_packages(),
    install_requires=[
        'requests>=2.31.0',
        'beautifulsoup4>=4.12.0',
        'lxml>=4.9.0',
        'semgrep>=1.45.0',
        'jinja2>=3.1.0',
        'groq>=0.4.0',
        'google-generativeai>=0.4.0',
        'rich>=13.0.0',
        'colorama>=0.4.6',
    ],
    entry_points={
        'console_scripts': [
            'WebVulnScanner=main:main',
        ],
    },
    python_requires='>=3.8',
)