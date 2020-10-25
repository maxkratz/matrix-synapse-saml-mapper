import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="dlz_saml",
    version="0.0.3",
    author="Maximilian Kratz",
    author_email="mkratz@fs-etit.de",
    description="Custom SAML mapping for the DLZ",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://chat.etit.tu-darmstadt.de",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)