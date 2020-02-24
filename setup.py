import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="kpxch",  # Replace with your own username
    version="0.0.3",
    author="cupnoodles",
    author_email="cupn8dles@gmail.com",
    description="KeePassXC CLI through NaCl and keepassxc-proxy",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/cupnoodles14/kpxch",
    packages=setuptools.find_packages(),
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Utilities",
    ],
    entry_points={"console_scripts": ["kpxch=kpxch.kpxch:main"]},
    install_requires=["pysodium"],
    python_requires=">=3.6",
)
