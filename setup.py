import os
from setuptools import find_packages, setup

version = '1.0.0'

install_requires = [
    # Minimum dependencies for the plugin to function correctly
    f'acme>=3.0.1',
    f'certbot>=3.0.1',
    "tencentcloud-sdk-python-common>=3.0.1227",
    "tencentcloud-sdk-python-dnspod>=3.0.1227",
]

if os.environ.get('SNAP_BUILD'):
    install_requires.append('packaging')

docs_extras = [
]

test_extras = [
    'pytest',  # for running tests
]

setup(
    name='certbot-dns-dnspod-109',
    version=version,
    description="Dnspod DNS Authenticator plugin for Certbot",
    url='https://github.com/10935336/certbot-dns-dnspod-109',
    author="10935336",
    author_email='109@pha.pub',
    python_requires='>=3.9',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'docs': docs_extras,
        'test': test_extras,
    },
    entry_points={
        'certbot.plugins': [
            'dns-dnspod-109 = certbot_dns_dnspod_109._internal.dns_dnspod:Authenticator',
        ],
    },
)
