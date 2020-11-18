import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="matrix-synapse-saml-mapper",
    version="0.0.5",
    author="Maximilian Kratz",
    author_email="mkratz@fs-etit.de",
    description="Custom SAML mapping provider for synapse installations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/maxkratz/matrix-synapse-saml-mapper",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)