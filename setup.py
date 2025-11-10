from setuptools import setup, find_packages
import os

# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
try:
    with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "Secomp - Revolutionary CLI for compliance and risk assessment in multi-cloud environments"

# Read requirements from requirements.txt
def read_requirements():
    with open('requirements.txt') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='secomp',
    version='0.1.0',
    description='Revolutionary CLI for compliance and risk assessment in multi-cloud environments',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Secomp Team',
    author_email='team@secomp.dev',
    url='https://github.com/secomp/secomp',
    packages=['secomp.secomp'],
    package_data={
        'secomp.secomp': ['*.txt', '*.md', '*.yml', '*.yaml', '*.py']
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
    ],
    python_requires='>=3.9',
    install_requires=read_requirements(),
    extras_require={
        'azure': ['azure-storage-blob==12.19.0', 'azure-identity==1.15.0'],
        'gcp': ['google-cloud-storage==3.5.0'],
        'all': ['azure-storage-blob==12.19.0', 'azure-identity==1.15.0', 'google-cloud-storage==3.5.0']
    },
    entry_points={
        'console_scripts': [
            'secomp=secomp.secomp.cli:cli',
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords='cybersecurity compliance gdpr aws azure gcp s3 blob storage risk-assessment devsecops',
    project_urls={
        'Homepage': 'https://github.com/wipenode/secomp',
        'Documentation': 'https://github.com/wipenode/secomp#readme',
        'Source': 'https://github.com/wipenode/secomp',
        'Tracker': 'https://github.com/wipenode/secomp/issues',
        'Discussions': 'https://github.com/wipenode/secomp/discussions',
    },
)
