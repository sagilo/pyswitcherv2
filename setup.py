from distutils.core import setup

setup(
  name = 'pyswitcherv2',
  packages = ['pyswitcherv2'], 
  version = '1.2',
  description = 'Control Switcher V2 water heater via Python',
  author = 'Sagi Lowenhardt',
  author_email = 'sagilo@gmail.com',
  url = 'https://github.com/sagilo/pyswitcherv2', 
  download_url = 'https://github.com/sagilo/pyswitcherv2/archive/1.2.tar.gz',
  data_files=[('pyswitcherv2', ['pyswitcherv2/credentials.json'])],
  keywords = ['switcher', 'switcherv2'],
  classifiers = [],
)

