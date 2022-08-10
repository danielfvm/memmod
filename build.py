from setuptools.extension import Extension

custom_extension = Extension(
    "memmod.memscan",
    sources=["memmod/memscan.c"],
)

def build(setup_kwargs):
    setup_kwargs.update({ "ext_modules": [custom_extension], })
