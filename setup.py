from distutils.core import setup

with open('requirements.txt', 'r') as f:
    requirements = f.read().splitlines()

with open('README.md', 'r') as f:
    readme_data = f.read()

setup(
    name = 'trackerjacker',
    packages = ['trackerjacker'],
    url = 'https://github.com/calebmadrigal/trackerjacker',
    version = '0.6.0',
    description = 'Finds and tracks wifi devices through raw 802.11 monitoring',
    long_description = readme_data,
    author = 'Caleb Madrigal',
    author_email = 'caleb.madrigal@gmail.com',
    license = 'MIT',
    keywords = ['hacking', 'network', 'wireless', 'packets', 'scapy'],
    install_requires = requirements,
    tests_require = requirements,
    classifiers = (
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: System :: Networking',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Security',
        'Operating System :: POSIX :: Linux'
    ),
)

