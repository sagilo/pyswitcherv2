"""////////////////////////////////////////////////////////////////////////////////////////////////
Home Assistant Custom Component for controlling Switcher 2

pyswitcherv2 Project: https://github.com/sagilo/pyswitcherv2
Created by: Sagi Lowenhardt

Installation:
Place this file in 'switch' directory under 'custom_components' directory, restart HomeAssistant:
/config/custom_components/switch/

yaml configuration example:

switch:
  - platform: switcher2
    friendly_name: name [optional]
    local_ip_addr: 
    phone_id: 
    device_id: 
    device_password:

////////////////////////////////////////////////////////////////////////////////////////////////"""

import logging

import voluptuous as vol

from homeassistant.components.switch import (PLATFORM_SCHEMA, SwitchDevice)
from homeassistant.const import (CONF_FRIENDLY_NAME)
import homeassistant.helpers.config_validation as cv

REQUIREMENTS = ['pyswitcherv2==1.2.9']

_LOGGER = logging.getLogger(__name__)

LOCAL_IP_ADDR = 'local_ip_addr'
PHONE_ID = 'phone_id'
DEVICE_ID = 'device_id'
DEVICE_PASSWORD = 'device_password'
DEFAULT_NAME = "Switcher2"

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_FRIENDLY_NAME, default=DEFAULT_NAME): cv.string,
    vol.Required(LOCAL_IP_ADDR): cv.string,
    vol.Required(PHONE_ID): cv.string,
    vol.Required(DEVICE_ID): cv.string,
    vol.Required(DEVICE_PASSWORD): cv.string
})
def setup_platform(hass, config, add_devices, discovery_info=None):
    from pyswitcherv2 import switcher as switcherv2

    local_ip_addr = config.get(LOCAL_IP_ADDR)
    phone_id = config.get(PHONE_ID)
    device_id = config.get(DEVICE_ID)
    device_password = config.get(DEVICE_PASSWORD)
    name = config.get(CONF_FRIENDLY_NAME)

    try:
        credentials = switcherv2.Credentials(phone_id, device_id, device_password, local_ip_addr)
        credentials.validate()
        switcher = switcherv2.Switcher(credentials)
        state = switcher.get_state()
        _LOGGER.info("Created Switcher device switch: %s", switcher)
        add_devices([Switcher2(name, switcher, state)])
    except Exception as e:
        _LOGGER.error('Could not configure Switcher device: %s' % e)
        return False

class Switcher2(SwitchDevice):

    def __init__(self, name, switcher, initial_state):
        self._name = name
        self._switcher = switcher
        self._state = initial_state

        _LOGGER.debug('New entity established: %s' % (self._switcher))

    @property
    def name(self):
        return self._name

    # Return true if the device is available for use.
    @property
    def available(self):
        return self._state is not None

    # Return True if unable to access real state of the entity.
    @property
    def assumed_state(self):
        return False

    # Return True if entity has to be polled for state.
    # False if entity pushes its state to HA.
    @property
    def should_poll(self):
        return True

    @property
    def is_on(self):
        return self._state

    def turn_on(self, **kwargs):
        _LOGGER.debug('Turning on')
        self._switcher.turn_on(0)
        self.schedule_update_ha_state(True)

    def turn_off(self, **kwargs):
        _LOGGER.debug('Turning off')
        self._switcher.turn_off()
        self.schedule_update_ha_state(True)

    def update(self):
        _LOGGER.debug('Updating state')
        self._state = self._switcher.get_state()
        _LOGGER.debug('Update state response: %s' % self._state)
        