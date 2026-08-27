from setuptools import setup, find_packages
from pathlib import Path

LONG_DESCRIPTION = Path("README.md").read_text(encoding="utf-8")

setup(
    name='webvulnscanner',
    version='1.0.0',
    description='Hybrid static + dynamic web vulnerability scanner with optional AI review',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    author='moadh704',
    url='https://github.com/moadh704/webvulnscanner',
    license='Personal Use License',
    keywords='security scanner vulnerability owasp sql-injection xss web pentest',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: Free For Educational Use',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
    ],
    py_modules=['main'],
    packages=find_packages(exclude=['tests', 'tests.*', 'docs', 'docs.*',
                                    'fixtures', 'fixtures.*']),
    package_data={
        'static': ['rules/*.yaml'],
        'templates': ['*.html'],
    },
    include_package_data=True,
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
        'streamlit>=1.30.0',
    ],
    entry_points={
        'console_scripts': [
            'wvs=main:main',
        ],
    },
    python_requires='>=3.8',
)
