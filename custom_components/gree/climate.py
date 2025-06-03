#!/usr/bin/python
# Do basic imports
import socket
import base64
import logging
import voluptuous as vol
from homeassistant.helpers import config_validation as cv, entity_platform, service

from homeassistant.components.climate import (ClimateEntity, ClimateEntityFeature, HVACMode, PLATFORM_SCHEMA)

from homeassistant.const import (ATTR_TEMPERATURE, ATTR_UNIT_OF_MEASUREMENT, CONF_HOST, CONF_MAC, CONF_NAME, CONF_PORT, CONF_TIMEOUT, STATE_OFF, STATE_ON, STATE_UNAVAILABLE)

from homeassistant.core import Event, EventStateChangedData, callback
from homeassistant.helpers.event import async_track_state_change_event
from homeassistant.helpers.restore_state import RestoreEntity
from Crypto.Cipher import AES
try: import simplejson
except ImportError: import json as simplejson
from datetime import timedelta

REQUIREMENTS = ['pycryptodome']

_LOGGER = logging.getLogger(__name__)

SUPPORT_FLAGS = ClimateEntityFeature.TARGET_TEMPERATURE | ClimateEntityFeature.FAN_MODE | ClimateEntityFeature.SWING_MODE | ClimateEntityFeature.TURN_ON | ClimateEntityFeature.TURN_OFF

DEFAULT_NAME = 'Gree Climate'

CONF_MIN_TEMP = 'min_temp'
CONF_MAX_TEMP = 'max_temp'
CONF_TARGET_TEMP_STEP = 'target_temp_step'
CONF_TEMP_SENSOR = 'temp_sensor'
CONF_ENCRYPTION_KEY = 'encryption_key'
CONF_UID = 'uid'
CONF_HORIZONTAL_SWING = 'horizontal_swing'
CONF_ENCRYPTION_VERSION = 'encryption_version'
CONF_DISABLE_AVAILABLE_CHECK  = 'disable_available_check'
CONF_MAX_ONLINE_ATTEMPTS = 'max_online_attempts'

DEFAULT_PORT = 7000
DEFAULT_TIMEOUT = 10
DEFAULT_TARGET_TEMP_STEP = 1

# update() interval
SCAN_INTERVAL = timedelta(seconds=60)

TEMP_OFFSET  = 40

DOMAIN = "climate"

SERVICE_LIGHT = 'set_light'
SERVICE_XFAN = 'set_xfan'
SERVICE_HEALTH = 'set_health'
SERVICE_POWERSAVE = 'set_powersave'
SERVICE_SLEEP = 'set_sleep'
SERVICE_EIGHTDEGHEAT = 'set_eightdegheat'
SERVICE_AIR = 'set_air'
SERVICE_AUTO_LIGHT = 'set_autolight'
SERVICE_AUTO_XFAN = 'set_autoxfan'
SERVICE_LIGHT_SENSOR = 'set_light_sensor'
SERVICE_ANTI_DIRECT_BLOW = 'set_anti_direct_blow'
SERVICE_TEMP_INCREMENT = 'temp_increment'
SERVICE_TEMP_DECREMENT = 'temp_decrement'

ATTR_SERVICE_MODE = 'mode'

# fixed values in gree mode lists
HVAC_MODES = [HVACMode.AUTO, HVACMode.COOL, HVACMode.DRY, HVACMode.FAN_ONLY, HVACMode.HEAT, HVACMode.OFF]

FAN_MODES = ['Auto', 'Low', 'Medium-Low', 'Medium', 'Medium-High', 'High', 'Turbo', 'Quiet']
SWING_MODES = ['Default', 'Swing in full range', 'Fixed in the upmost position', 'Fixed in the middle-up position', 'Fixed in the middle position', 'Fixed in the middle-low position', 'Fixed in the lowest position', 'Swing in the downmost region', 'Swing in the middle-low region', 'Swing in the middle region', 'Swing in the middle-up region', 'Swing in the upmost region']
SWING_HORIZONTAL_MODES = ['Default', 'Full swing', 'Fixed in the leftmost position', 'Fixed in the middle-left position', 'Fixed in the middle postion','Fixed in the middle-right position', 'Fixed in the rightmost position']

GCM_IV = b'\x54\x40\x78\x44\x49\x67\x5a\x51\x6c\x5e\x63\x13'
GCM_ADD = b'qualcomm-test'

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_NAME, default=DEFAULT_NAME): cv.string,
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_PORT, default=DEFAULT_PORT): cv.positive_int,
    vol.Required(CONF_MAC): cv.string,
    vol.Optional(CONF_TIMEOUT, default=DEFAULT_TIMEOUT): cv.positive_int,
    vol.Optional(CONF_MIN_TEMP, default=16): cv.positive_int,
    vol.Optional(CONF_MAX_TEMP, default=30): cv.positive_int,
    vol.Optional(CONF_TARGET_TEMP_STEP, default=DEFAULT_TARGET_TEMP_STEP): vol.Coerce(float),
    vol.Optional(CONF_TEMP_SENSOR): cv.entity_id,
    vol.Optional(CONF_ENCRYPTION_KEY): cv.string,
    vol.Optional(CONF_UID): cv.positive_int,
    vol.Optional(CONF_ENCRYPTION_VERSION, default=1): cv.positive_int,
    vol.Optional(CONF_HORIZONTAL_SWING, default=False): cv.boolean,
    vol.Optional(CONF_DISABLE_AVAILABLE_CHECK, default=False): cv.boolean,
    vol.Optional(CONF_MAX_ONLINE_ATTEMPTS, default=3): cv.positive_int
})

async def async_setup_platform(hass, config, async_add_devices, discovery_info=None):
    _LOGGER.info('Setting up Gree climate platform')
    name = config.get(CONF_NAME)
    ip_addr = config.get(CONF_HOST)
    port = config.get(CONF_PORT)
    mac_addr = config.get(CONF_MAC).encode().replace(b':', b'')
    timeout = config.get(CONF_TIMEOUT)
    min_temp = config.get(CONF_MIN_TEMP)
    max_temp = config.get(CONF_MAX_TEMP)
    target_temp_step = config.get(CONF_TARGET_TEMP_STEP)
    temp_sensor_entity_id = config.get(CONF_TEMP_SENSOR)
    hvac_modes = HVAC_MODES
    fan_modes = FAN_MODES
    swing_modes = SWING_MODES
    swing_horizontal_modes = SWING_HORIZONTAL_MODES
    encryption_key = config.get(CONF_ENCRYPTION_KEY)
    uid = config.get(CONF_UID)
    horizontal_swing = config.get(CONF_HORIZONTAL_SWING)
    encryption_version = config.get(CONF_ENCRYPTION_VERSION)
    disable_available_check = config.get(CONF_DISABLE_AVAILABLE_CHECK)
    max_online_attempts = config.get(CONF_MAX_ONLINE_ATTEMPTS)

    component = hass.data[DOMAIN]
    await component.async_setup(config)
    component.async_register_entity_service(SERVICE_AUTO_LIGHT,{vol.Required(ATTR_SERVICE_MODE): cv.string,},"async_set_autolight_service",)
    component.async_register_entity_service(SERVICE_AUTO_XFAN,{vol.Required(ATTR_SERVICE_MODE): cv.string,},"async_set_autoxfan_service",)
    component.async_register_entity_service(SERVICE_LIGHT_SENSOR,{vol.Required(ATTR_SERVICE_MODE): cv.string,},"async_set_light_sensor_service",)
    component.async_register_entity_service(SERVICE_ANTI_DIRECT_BLOW,{vol.Required(ATTR_SERVICE_MODE): cv.string,},"async_set_anti_direct_blow_service",)
    component.async_register_entity_service(SERVICE_LIGHT,{vol.Required(ATTR_SERVICE_MODE): cv.string,},"async_set_light_service",)
    component.async_register_entity_service(SERVICE_XFAN,{vol.Required(ATTR_SERVICE_MODE): cv.string,},"async_set_xfan_service",)
    component.async_register_entity_service(SERVICE_HEALTH,{vol.Required(ATTR_SERVICE_MODE): cv.string,},"async_set_health_service",)
    component.async_register_entity_service(SERVICE_POWERSAVE,{vol.Required(ATTR_SERVICE_MODE): cv.string,},"async_set_powersave_service",)
    component.async_register_entity_service(SERVICE_SLEEP,{vol.Required(ATTR_SERVICE_MODE): cv.string,},"async_set_sleep_service",)
    component.async_register_entity_service(SERVICE_EIGHTDEGHEAT,{vol.Required(ATTR_SERVICE_MODE): cv.string,},"async_set_eightdegheat_service",)
    component.async_register_entity_service(SERVICE_AIR,{vol.Required(ATTR_SERVICE_MODE): cv.string,},"async_set_air_service",)
    component.async_register_entity_service(SERVICE_TEMP_INCREMENT,{},"async_temp_increment",)
    component.async_register_entity_service(SERVICE_TEMP_DECREMENT,{},"async_temp_decrement",)
    
    _LOGGER.info('Adding Gree climate device to hass')

    async_add_devices([
        GreeClimate(hass, name, ip_addr, port, mac_addr, timeout, min_temp, max_temp, target_temp_step, temp_sensor_entity_id, hvac_modes, fan_modes, swing_modes, swing_horizontal_modes, horizontal_swing, encryption_version, disable_available_check, max_online_attempts, encryption_key, uid)
    ])

class GreeClimate(ClimateEntity, RestoreEntity):

    def __init__(self, hass, name, ip_addr, port, mac_addr, timeout, min_temp, max_temp, target_temp_step, temp_sensor_entity_id, hvac_modes, fan_modes, swing_modes, swing_horizontal_modes, horizontal_swing, encryption_version, disable_available_check, max_online_attempts, encryption_key=None, uid=None):
        _LOGGER.info('Initialize the GREE climate device')
        self.hass = hass
        self._name = name
        self._ip_addr = ip_addr
        self._port = port
        self._mac_addr = mac_addr.decode('utf-8').lower()
        self._timeout = timeout
        self._unique_id = 'climate.gree_' + mac_addr.decode('utf-8').lower()
        self._device_online = None
        self._online_attempts = 0
        self._max_online_attempts = max_online_attempts
        self._disable_available_check = disable_available_check
        self._min_temp = min_temp
        self._max_temp = max_temp
        self._target_temperature = None
        self._target_temperature_step = target_temp_step
        self._unit_of_measurement = '°C'
        self._hvac_modes = hvac_modes
        self._hvac_mode = None
        self._fan_modes = fan_modes
        self._fan_mode = None
        self._swing_modes = swing_modes
        self._swing_mode = None
        self._swing_horizontal_modes = swing_horizontal_modes
        self._swing_horizontal_mode = None
        self._horizontal_swing = horizontal_swing
        self._has_temp_sensor = None
        self._has_anti_direct_blow = None
        self._has_light_sensor = None

        self._temp_sensor_entity_id = temp_sensor_entity_id

        self._attributes = {
            'auto_light': False,
            'auto_xfan': False,
            'light_sensor': None,
            'light': None,
            'xfan': None,
            'health': None,
            'powersave': None,
            'sleep': None,
            'eightdegheat': None,
            'air': None,
            'anti_direct_blow': None
        }

        self._current_temperature = None
        self._firstTimeRun = True
        self._enable_turn_on_off_backwards_compatibility = False
        self.encryption_version = encryption_version
        self.CIPHER = None

        if encryption_key:
            _LOGGER.info('Using configured encryption key: {}'.format(encryption_key))
            self._encryption_key = encryption_key.encode("utf8")
            if encryption_version == 1:
                # Cipher to use to encrypt/decrypt
                self.CIPHER = AES.new(self._encryption_key, AES.MODE_ECB)
            elif encryption_version != 2:
                _LOGGER.error('Encryption version %s is not implemented.' % encryption_version)
        else:
            self._encryption_key = None
        
        if uid:
            self._uid = uid
        else:
            self._uid = 0
        
        self._acOptions = { 'Pow': None, 'Mod': None, 'SetTem': None, 'WdSpd': None, 'Air': None, 'Blo': None, 'Health': None, 'SwhSlp': None, 'Lig': None, 'SwingLfRig': None, 'SwUpDn': None, 'Quiet': None, 'Tur': None, 'StHt': None, 'TemUn': None, 'HeatCoolType': None, 'TemRec': None, 'SvSt': None, 'SlpMod': None }
        self._optionsToFetch = ["Pow","Mod","SetTem","WdSpd","Air","Blo","Health","SwhSlp","Lig","SwingLfRig","SwUpDn","Quiet","Tur","StHt","TemUn","HeatCoolType","TemRec","SvSt","SlpMod"]

        if temp_sensor_entity_id:
            _LOGGER.info('Setting up temperature sensor: ' + str(temp_sensor_entity_id))
            async_track_state_change_event(hass, temp_sensor_entity_id, self._async_temp_sensor_changed)

    async def async_set_autolight_service(self, mode : str | None = None) -> None:
        if not mode in ('on','off','toggle'):
            raise ValueError("Service parameter value invalid. Accepted parameter values: on, off, toggle")
        _LOGGER.info('Running set_autolight service with parameter: ' + str(mode))
        if mode == 'on':
            self._attributes['auto_light'] = True
        elif mode == 'off':
            self._attributes['auto_light'] = False
        elif mode == 'toggle':
            self._attributes['auto_light'] = not self._attributes['auto_light']
        self.SyncState({'Lig': 0 if self.hvac_mode == HVACMode.OFF else 1})

    async def async_set_autoxfan_service(self, mode : str | None = None) -> None:
        if not mode in ('on','off','toggle'):
            raise ValueError("Service parameter value invalid. Accepted parameter values: on, off, toggle")
        _LOGGER.info('Running set_autoxfan service with parameter: ' + str(mode))
        if mode == 'on':
            self._attributes['auto_xfan'] = True
        elif mode == 'off':
            self._attributes['auto_xfan'] = False
        elif mode == 'toggle':
            self._attributes['auto_xfan'] = not self._attributes['auto_xfan']
        if (self._hvac_mode == HVACMode.COOL) or (self._hvac_mode == HVACMode.DRY):
            self.SyncState({'Blo': int(self._attributes['auto_xfan'])})

    async def async_set_light_sensor_service(self, mode : str | None = None) -> None:
        if not mode in ('on','off','toggle'):
            raise ValueError("Service parameter value invalid. Accepted parameter values: on, off, toggle")
        _LOGGER.info('Running set_light_sensor service with parameter: ' + str(mode))
        if mode == 'on':
            self._attributes['light_sensor'] = STATE_ON
        elif mode == 'off':
            self._attributes['light_sensor'] = STATE_OFF
        elif mode == 'toggle':
            if self._attributes['light_sensor'] == STATE_ON:
                self._attributes['light_sensor'] = STATE_OFF
            else:
                self._attributes['light_sensor'] = STATE_ON

    async def async_set_anti_direct_blow_service(self, mode : str | None = None) -> None:
        if not mode in ('on','off','toggle'):
            raise ValueError("Service parameter value invalid. Accepted parameter values: on, off, toggle")
        if self._has_anti_direct_blow:
            _LOGGER.info('Running set_anti_direct_blow service with parameter: ' + str(mode))
            if mode == 'on':
                self.SyncState({'AntiDirectBlow': 1})
            elif mode == 'off':
                self.SyncState({'AntiDirectBlow': 0})
            elif mode == 'toggle':
                if self._attributes['anti_direct_blow'] == STATE_ON:
                    self.SyncState({'AntiDirectBlow': 0})
                else:
                    self.SyncState({'AntiDirectBlow': 1})
        else:
            _LOGGER.info('Device does not have an anti direct blow function')

    async def async_set_light_service(self, mode : str | None = None) -> None:
        if not mode in ('on','off','toggle'):
            raise ValueError("Service parameter value invalid. Accepted parameter values: on, off, toggle")
        _LOGGER.info('Running set_light service with parameter: ' + str(mode))
        if mode == 'on':
            self.SyncState({'Lig': 1})
        elif mode == 'off':
            self.SyncState({'Lig': 0})
        elif mode == 'toggle':
            if self._attributes['light'] == STATE_ON:
                self.SyncState({'Lig': 0})
            else:
                self.SyncState({'Lig': 1})

    async def async_set_xfan_service(self, mode : str | None = None) -> None:
        if not mode in ('on','off','toggle'):
            raise ValueError("Service parameter value invalid. Accepted parameter values: on, off, toggle")
        _LOGGER.info('Running set_xfan service with parameter: ' + str(mode))
        if mode == 'on':
            self.SyncState({'Blo': 1})
        elif mode == 'off':
            self.SyncState({'Blo': 0})
        elif mode == 'toggle':
            if self._attributes['xfan'] == STATE_ON:
                self.SyncState({'Blo': 0})
            else:
                self.SyncState({'Blo': 1})

    async def async_set_health_service(self, mode : str | None = None) -> None:
        if not mode in ('on','off','toggle'):
            raise ValueError("Service parameter value invalid. Accepted parameter values: on, off, toggle")
        _LOGGER.info('Running set_health service with parameter: ' + str(mode))
        if mode == 'on':
            self.SyncState({'Health': 1})
        elif mode == 'off':
            self.SyncState({'Health': 0})
        elif mode == 'toggle':
            if self._attributes['health'] == STATE_ON:
                self.SyncState({'Health': 0})
            else:
                self.SyncState({'Health': 1})

    async def async_set_powersave_service(self, mode : str | None = None) -> None:
        if not mode in ('on','off','toggle'):
            raise ValueError("Service parameter value invalid. Accepted parameter values: on, off, toggle")
        _LOGGER.info('Running set_powersave service with parameter: ' + str(mode))
        if mode == 'on':
            self.SyncState({'SvSt': 1})
        elif mode == 'off':
            self.SyncState({'SvSt': 0})
        elif mode == 'toggle':
            if self._attributes['powersave'] == STATE_ON:
                self.SyncState({'SvSt': 0})
            else:
                self.SyncState({'SvSt': 1})

    async def async_set_sleep_service(self, mode : str | None = None) -> None:
        if not mode in ('on','off','toggle'):
            raise ValueError("Service parameter value invalid. Accepted parameter values: on, off, toggle")
        _LOGGER.info('Running set_sleep service with parameter: ' + str(mode))
        if mode == 'on':
            self.SyncState({'SwhSlp': 1, 'SlpMod': 1})
        elif mode == 'off':
            self.SyncState({'SwhSlp': 0, 'SlpMod': 0})
        elif mode == 'toggle':
            if self._attributes['sleep'] == STATE_ON:
                self.SyncState({'SwhSlp': 0, 'SlpMod': 0})
            else:
                self.SyncState({'SwhSlp': 1, 'SlpMod': 1})

    async def async_set_eightdegheat_service(self, mode : str | None = None) -> None:
        if not mode in ('on','off','toggle'):
            raise ValueError("Service parameter value invalid. Accepted parameter values: on, off, toggle")
        _LOGGER.info('Running set_eigthdegheat service with parameter: ' + str(mode))
        if mode == 'on':
            self.SyncState({'StHt': 1})
        elif mode == 'off':
            self.SyncState({'StHt': 0})
        elif mode == 'toggle':
            if self._attributes['eightdegheat'] == STATE_ON:
                self.SyncState({'StHt': 0})
            else:
                self.SyncState({'StHt': 1})

    async def async_set_air_service(self, mode : str | None = None) -> None:
        if not mode in ('on','off','toggle'):
            raise ValueError("Service parameter value invalid. Accepted parameter values: on, off, toggle")
        _LOGGER.info('Running set_air service with parameter: ' + str(mode))
        if mode == 'on':
            self.SyncState({'Air': 1})
        elif mode == 'off':
            self.SyncState({'Air': 0})
        elif mode == 'toggle':
            if self._attributes['air'] == STATE_ON:
                self.SyncState({'Air': 0})
            else:
                self.SyncState({'Air': 1})

    async def async_temp_increment(self) -> None:
        if self._acOptions['SetTem'] > self._min_temp and self._acOptions['SetTem'] < self._max_temp:
            self.SyncState({'SetTem': self._acOptions['SetTem'] + 1})

    async def async_temp_decrement(self) -> None:
        if self._acOptions['SetTem'] > self._min_temp and self._acOptions['SetTem'] < self._max_temp:
            self.SyncState({'SetTem': self._acOptions['SetTem'] - 1})         

    # Pad helper method to help us get the right string for encrypting
    def Pad(self, s):
        aesBlockSize = 16
        return s + (aesBlockSize - len(s) % aesBlockSize) * chr(aesBlockSize - len(s) % aesBlockSize)            

    def FetchResult(self, cipher, ip_addr, port, timeout, json):
        _LOGGER.info('Fetching(%s, %s, %s, %s)' % (ip_addr, port, timeout, json))
        clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clientSock.settimeout(timeout)
        clientSock.sendto(bytes(json, "utf-8"), (ip_addr, port))
        data, addr = clientSock.recvfrom(64000)
        receivedJson = simplejson.loads(data)
        clientSock.close()
        pack = receivedJson['pack']
        base64decodedPack = base64.b64decode(pack)
        decryptedPack = cipher.decrypt(base64decodedPack)
        if self.encryption_version == 2:
            tag = receivedJson['tag']
            cipher.verify(base64.b64decode(tag))
        decodedPack = decryptedPack.decode("utf-8")
        replacedPack = decodedPack.replace('\x0f', '').replace(decodedPack[decodedPack.rindex('}')+1:], '')
        loadedJsonPack = simplejson.loads(replacedPack)  
        return loadedJsonPack

    def GetDeviceKey(self):
        _LOGGER.info('Retrieving HVAC encryption key')
        GENERIC_GREE_DEVICE_KEY = "a3K8Bx%2r8Y7#xDh"
        cipher = AES.new(GENERIC_GREE_DEVICE_KEY.encode("utf8"), AES.MODE_ECB)
        pack = base64.b64encode(cipher.encrypt(self.Pad('{"mac":"' + str(self._mac_addr) + '","t":"bind","uid":0}').encode("utf8"))).decode('utf-8')
        jsonPayloadToSend = '{"cid": "app","i": 1,"pack": "' + pack + '","t":"pack","tcid":"' + str(self._mac_addr) + '","uid": 0}'
        try:
            self._encryption_key = self.FetchResult(cipher, self._ip_addr, self._port, self._timeout, jsonPayloadToSend)['key'].encode("utf8")
        except:
            _LOGGER.info('Error getting device encryption key!')
            self._device_online = False
            self._online_attempts = 0
            return False
        else:
            _LOGGER.info('Fetched device encrytion key: %s' % str(self._encryption_key))
            self.CIPHER = AES.new(self._encryption_key, AES.MODE_ECB)
            self._device_online = True
            self._online_attempts = 0
            return True
        
    def GetGCMCipher(self, key):
        cipher = AES.new(key, AES.MODE_GCM, nonce=GCM_IV)
        cipher.update(GCM_ADD)
        return cipher

    def EncryptGCM(self, key, plaintext):
        encrypted_data, tag = self.GetGCMCipher(key).encrypt_and_digest(plaintext.encode("utf8"))
        pack = base64.b64encode(encrypted_data).decode('utf-8')
        tag = base64.b64encode(tag).decode('utf-8')
        return (pack, tag)

    def GetDeviceKeyGCM(self):
        _LOGGER.info('Retrieving HVAC encryption key')
        GENERIC_GREE_DEVICE_KEY = b'{yxAHAY_Lm6pbC/<'
        plaintext = '{"cid":"' + str(self._mac_addr) + '", "mac":"' + str(self._mac_addr) + '","t":"bind","uid":0}'
        pack, tag = self.EncryptGCM(GENERIC_GREE_DEVICE_KEY, plaintext)
        jsonPayloadToSend = '{"cid": "app","i": 1,"pack": "' + pack + '","t":"pack","tcid":"' + str(self._mac_addr) + '","uid": 0, "tag" : "' + tag + '"}'
        try:
            self._encryption_key = self.FetchResult(self.GetGCMCipher(GENERIC_GREE_DEVICE_KEY), self._ip_addr, self._port, self._timeout, jsonPayloadToSend)['key'].encode("utf8")
        except:
            _LOGGER.info('Error getting device encryption key!')
            self._device_online = False
            self._online_attempts = 0
            return False
        else:
            _LOGGER.info('Fetched device encrytion key: %s' % str(self._encryption_key))
            self._device_online = True
            self._online_attempts = 0
            return True

    def GreeGetValues(self, propertyNames):
        plaintext = '{"cols":' + simplejson.dumps(propertyNames) + ',"mac":"' + str(self._mac_addr) + '","t":"status"}'
        if self.encryption_version == 1:
            cipher = self.CIPHER
            jsonPayloadToSend = '{"cid":"app","i":0,"pack":"' + base64.b64encode(cipher.encrypt(self.Pad(plaintext).encode("utf8"))).decode('utf-8') + '","t":"pack","tcid":"' + str(self._mac_addr) + '","uid":{}'.format(self._uid) + '}'
        elif self.encryption_version == 2:
            pack, tag = self.EncryptGCM(self._encryption_key, plaintext)
            jsonPayloadToSend = '{"cid":"app","i":0,"pack":"' + pack + '","t":"pack","tcid":"' + str(self._mac_addr) + '","uid":{}'.format(self._uid) + ',"tag" : "' + tag + '"}'
            cipher = self.GetGCMCipher(self._encryption_key)
        return self.FetchResult(cipher, self._ip_addr, self._port, self._timeout, jsonPayloadToSend)['dat']

    def SetAcOptions(self, acOptions, newOptionsToOverride, optionValuesToOverride = None):
        if not (optionValuesToOverride is None):
            _LOGGER.info('Setting acOptions with retrieved HVAC values')
            for key in newOptionsToOverride:
                _LOGGER.info('Setting %s: %s' % (key, optionValuesToOverride[newOptionsToOverride.index(key)]))
                acOptions[key] = optionValuesToOverride[newOptionsToOverride.index(key)]
            _LOGGER.info('Done setting acOptions')
        else:
            _LOGGER.info('Overwriting acOptions with new settings')
            for key, value in newOptionsToOverride.items():
                _LOGGER.info('Overwriting %s: %s' % (key, value))
                acOptions[key] = value
            _LOGGER.info('Done overwriting acOptions')
        return acOptions
        
    def SendStateToAc(self, timeout):
        opt = '"Pow","Mod","SetTem","WdSpd","Air","Blo","Health","SwhSlp","Lig","SwingLfRig","SwUpDn","Quiet","Tur","StHt","TemUn","HeatCoolType","TemRec","SvSt","SlpMod"'
        p = '{Pow},{Mod},{SetTem},{WdSpd},{Air},{Blo},{Health},{SwhSlp},{Lig},{SwingLfRig},{SwUpDn},{Quiet},{Tur},{StHt},{TemUn},{HeatCoolType},{TemRec},{SvSt},{SlpMod}'.format(**self._acOptions)
        if self._has_anti_direct_blow:
            opt += ',"AntiDirectBlow"'
            p += ',' + str(self._acOptions['AntiDirectBlow'])
        if self._has_light_sensor is True:
            opt += ',"LigSen"'
            p += ',' + str(self._acOptions['LigSen'])
        statePackJson = '{"opt":[' + opt + '],"p":[' + p + '],"t":"cmd"}'
        if self.encryption_version == 1:
            cipher = self.CIPHER
            sentJsonPayload = '{"cid":"app","i":0,"pack":"' + base64.b64encode(cipher.encrypt(self.Pad(statePackJson).encode("utf8"))).decode('utf-8') + '","t":"pack","tcid":"' + str(self._mac_addr) + '","uid":{}'.format(self._uid) + '}'
        elif self.encryption_version == 2:
            pack, tag = self.EncryptGCM(self._encryption_key, statePackJson)
            sentJsonPayload = '{"cid":"app","i":0,"pack":"' + pack + '","t":"pack","tcid":"' + str(self._mac_addr) + '","uid":{}'.format(self._uid) + ',"tag":"' + tag +'"}'
            cipher = self.GetGCMCipher(self._encryption_key)
        receivedJsonPayload = self.FetchResult(cipher, self._ip_addr, self._port, timeout, sentJsonPayload)
        _LOGGER.info('Done sending state to HVAC: ' + str(receivedJsonPayload))

    def SyncState(self, acOptions = {}):
        #Fetch current settings from HVAC
        _LOGGER.info('Starting SyncState')

        if not self._temp_sensor_entity_id:
            if self._has_temp_sensor is None:
                _LOGGER.info('Attempt to check whether device has an built-in temperature sensor')
                try:
                    temp_sensor = self.GreeGetValues(["TemSen"])
                except:
                    _LOGGER.info('Could not determine whether device has an built-in temperature sensor. Retrying at next update()')
                else:
                    if temp_sensor:
                        self._has_temp_sensor = True
                        self._acOptions.update({'TemSen': None})
                        self._optionsToFetch.append("TemSen")
                        _LOGGER.info('Device has an built-in temperature sensor')
                    else:
                        self._has_temp_sensor = False
                        _LOGGER.info('Device has no built-in temperature sensor')

        if self._has_anti_direct_blow is None:
            _LOGGER.info('Attempt to check whether device has an anti direct blow feature')
            try:
                anti_direct_blow = self.GreeGetValues(["AntiDirectBlow"])
            except:
                _LOGGER.info('Could not determine whether device has an anti direct blow feature. Retrying at next update()')
            else:
                if anti_direct_blow:
                    self._has_anti_direct_blow = True
                    self._acOptions.update({'AntiDirectBlow': None})
                    self._optionsToFetch.append("AntiDirectBlow")
                    _LOGGER.info('Device has an anti direct blow feature')
                else:
                    self._has_anti_direct_blow = False
                    _LOGGER.info('Device has no anti direct blow feature')

        if self._has_light_sensor is None:
            _LOGGER.info('Attempt to check whether device has an built-in light sensor')
            try:
                light_sensor = self.GreeGetValues(["LigSen"])
            except:
                _LOGGER.info('Could not determine whether device has an built-in light sensor. Retrying at next update()')
            else:
                if light_sensor:
                    self._has_light_sensor = True
                    self._acOptions.update({'LigSen': None})
                    self._optionsToFetch.append("LigSen")
                    _LOGGER.info('Device has an built-in light sensor')
                else:
                    self._has_light_sensor = False
                    _LOGGER.info('Device has no built-in light sensor')

        optionsToFetch = self._optionsToFetch

        try:
            currentValues = self.GreeGetValues(optionsToFetch)
        except:
            _LOGGER.info('Could not connect with device. ')
            if not self._disable_available_check:
                self._online_attempts +=1
                if (self._online_attempts == self._max_online_attempts):
                    _LOGGER.info('Could not connect with device %s times. Set it as offline.' % self._max_online_attempts)
                    self._device_online = False
                    self._online_attempts = 0
        else:
            if not self._disable_available_check:
                if not self._device_online:
                    self._device_online = True
                    self._online_attempts = 0
            # Set latest status from device
            self._acOptions = self.SetAcOptions(self._acOptions, optionsToFetch, currentValues)

            # Overwrite status with our choices
            if not(acOptions == {}):
                self._acOptions = self.SetAcOptions(self._acOptions, acOptions)

            # Initialize the receivedJsonPayload variable (for return)
            receivedJsonPayload = ''

            # If not the first (boot) run, update state towards the HVAC
            if not (self._firstTimeRun):
                if not(acOptions == {}):
                    # loop used to send changed settings from HA to HVAC
                    self.SendStateToAc(self._timeout)
            else:
                # loop used once for Gree Climate initialisation only
                self._firstTimeRun = False

            # Sync set temperature to HA. If 8℃ heating is active we set the temp in HA to 8℃ so that it shows the same as the AC display.
            if (int(self._acOptions['StHt']) == 1):
                self._target_temperature = 8
                _LOGGER.info('HA target temp set according to HVAC state to 8℃ since 8℃ heating mode is active')
            else:
                self._target_temperature = self._acOptions['SetTem']
                _LOGGER.info('HA target temp set according to HVAC state to: ' + str(self._acOptions['SetTem']))

            # Update current temperature with built-in temp sensor
            if not self._temp_sensor_entity_id:
                if self._has_temp_sensor:
                    temp = self._acOptions['TemSen'] if self._acOptions['TemSen'] <= TEMP_OFFSET else self._acOptions['TemSen'] - TEMP_OFFSET
                    self._current_temperature = self.hass.config.units.temperature(float(temp), self._unit_of_measurement)
                    _LOGGER.info('HA current temperature set with device built-in temperature sensor state : ' + str(self._current_temperature))

            # Sync current HVAC light option to HA
            if (self._acOptions['Lig'] == 1):
                self._attributes['light'] = STATE_ON
            else:
                self._attributes['light'] = STATE_OFF
            _LOGGER.info('HA light option set according to HVAC state to: ' + str(self._attributes['light']))
            # Sync current HVAC xfan option to HA
            if (self._acOptions['Blo'] == 1):
                self._attributes['xfan'] = STATE_ON
            else:
                self._attributes['xfan'] = STATE_OFF
            _LOGGER.info('HA xfan option set according to HVAC state to: ' + str(self._attributes['xfan']))
            # Sync current HVAC health option to HA
            if (self._acOptions['Health'] == 1):
                self._attributes['health'] = STATE_ON
            else:
                self._attributes['health'] = STATE_OFF
            _LOGGER.info('HA health option set according to HVAC state to: ' + str(self._attributes['health']))
            # Sync current HVAC powersave option to HA
            if (self._acOptions['SvSt'] == 1):
                self._attributes['powersave'] = STATE_ON
            else:
                self._attributes['powersave'] = STATE_OFF
            _LOGGER.info('HA powersave option set according to HVAC state to: ' + str(self._attributes['powersave']))
            # Sync current HVAC sleep option to HA
            if (self._acOptions['SwhSlp'] == 1) and (self._acOptions['SlpMod'] == 1):
                self._attributes['sleep'] = STATE_ON
            else:
                self._attributes['sleep'] = STATE_OFF
            _LOGGER.info('HA sleep option set according to HVAC state to: ' + str(self._attributes['sleep']))
            # Sync current HVAC 8℃ heat option to HA
            if (self._acOptions['StHt'] == 1):
                self._attributes['eightdegheat'] = STATE_ON
            else:
                self._attributes['eightdegheat'] = STATE_OFF
            _LOGGER.info('HA 8℃ heat option set according to HVAC state to: ' + str(self._attributes['eightdegheat']))
            # Sync current HVAC air option to HA
            if (self._acOptions['Air'] == 1):
                self._attributes['air'] = STATE_ON
            else:
                self._attributes['air'] = STATE_OFF
            _LOGGER.info('HA air option set according to HVAC state to: ' + str(self._attributes['air']))
            # Sync current HVAC anti direct blow option to HA
            if self._has_anti_direct_blow:
                if (self._acOptions['AntiDirectBlow'] == 1):
                    self._attributes['anti_direct_blow'] = STATE_ON
                else:
                    self._attributes['anti_direct_blow'] = STATE_OFF
                _LOGGER.info('HA anti direct blow option set according to HVAC state to: ' + str(self._attributes['anti_direct_blow']))

            # Sync current HVAC operation mode to HA
            if (self._acOptions['Pow'] == 0):
                self._hvac_mode = HVACMode.OFF
            else:
                self._hvac_mode = self._hvac_modes[self._acOptions['Mod']]
            _LOGGER.info('HA operation mode set according to HVAC state to: ' + str(self._hvac_mode))

            # Sync current HVAC Swing mode state to HA
            self._swing_mode = self._swing_modes[self._acOptions['SwUpDn']]
            _LOGGER.info('HA swing mode set according to HVAC state to: ' + str(self._swing_mode))

            if self._horizontal_swing:
                # Sync current HVAC Swing horizontal mode state to HA
                self._swing_horizontal_mode = self._swing_horizontal_modes[self._acOptions['SwingLfRig']]
                _LOGGER.info('HA swing horizontal mode set according to HVAC state to: ' + str(self._swing_horizontal_mode))

            # Sync current HVAC Fan mode state to HA
            if (int(self._acOptions['Tur']) == 1):
                self._fan_mode = 'Turbo'
            elif (int(self._acOptions['Quiet']) >= 1):
                self._fan_mode = 'Quiet'
            else:
                self._fan_mode = self._fan_modes[int(self._acOptions['WdSpd'])]
            _LOGGER.info('HA fan mode set according to HVAC state to: ' + str(self._fan_mode))

            _LOGGER.info('Finished SyncState')
            return receivedJsonPayload

    async def _async_temp_sensor_changed(self, event: Event[EventStateChangedData]) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        s = str(old_state.state) if hasattr(old_state,'state') else "None"
        _LOGGER.info('temp_sensor state changed | ' + str(entity_id) + ' from ' + s + ' to ' + str(new_state.state))
        # Handle temperature changes.
        if new_state is None:
            return
        self._async_update_current_temp(new_state)
        return self.schedule_update_ha_state(True)
        
    @callback
    def _async_update_current_temp(self, state):
        _LOGGER.info('Thermostat updated with changed temp_sensor state | ' + str(state.state))
        unit = state.attributes.get(ATTR_UNIT_OF_MEASUREMENT)
        try:
            _state = state.state
            _LOGGER.info('Current state temp_sensor: ' + _state)
            if self.represents_float(_state):
                self._current_temperature = self.hass.config.units.temperature(
                    float(_state), unit)
                _LOGGER.info('Current temp: ' + str(self._current_temperature))
        except ValueError as ex:
            _LOGGER.error('Unable to update from temp_sensor: %s' % ex)

    def represents_float(self, s):
        _LOGGER.info('temp_sensor state represents_float |' + str(s))
        try: 
            float(s)
            return True
        except ValueError:
            return False

    @property
    def should_poll(self):
        _LOGGER.info('should_poll()')
        # Return the polling state.
        return True

    @property
    def extra_state_attributes(self):
        return self._attributes

    @property
    def available(self):
        if self._disable_available_check:
            return True
        else:
            if self._device_online:
                _LOGGER.info('available(): Device is online')
                return True
            else:
                _LOGGER.info('available(): Device is offline')
                return False

    def update(self):
        _LOGGER.info('update()')
        if not self._encryption_key:
            if self.encryption_version == 1:
                if self.GetDeviceKey():
                    self.SyncState()
            elif self.encryption_version == 2:
                if self.GetDeviceKeyGCM():
                    self.SyncState()
            else:
                _LOGGER.error('Encryption version %s is not implemented.' % encryption_version)
        else:
            self.SyncState()

    @property
    def name(self):
        _LOGGER.info('name(): ' + str(self._name))
        # Return the name of the climate device.
        return self._name

    @property
    def temperature_unit(self):
        _LOGGER.info('temperature_unit(): ' + str(self._unit_of_measurement))
        # Return the unit of measurement.
        return self._unit_of_measurement

    @property
    def current_temperature(self):
        _LOGGER.info('current_temperature(): ' + str(self._current_temperature))
        # Return the current temperature.
        return self._current_temperature

    @property
    def min_temp(self):
        _LOGGER.info('min_temp(): ' + str(self._min_temp))
        # Return the minimum temperature.
        return self._min_temp
        
    @property
    def max_temp(self):
        _LOGGER.info('max_temp(): ' + str(self._max_temp))
        # Return the maximum temperature.
        return self._max_temp
        
    @property
    def target_temperature(self):
        _LOGGER.info('target_temperature(): ' + str(self._target_temperature))
        # Return the temperature we try to reach.
        return self._target_temperature
        
    @property
    def target_temperature_step(self):
        _LOGGER.info('target_temperature_step(): ' + str(self._target_temperature_step))
        # Return the supported step of target temperature.
        return self._target_temperature_step

    @property
    def hvac_mode(self) -> str | None:
        _LOGGER.info('hvac_mode(): ' + str(self._hvac_mode))
        # Return current operation mode ie. heat, cool, idle.
        return self._hvac_mode

    @property
    def hvac_modes(self) -> list[str] | None:
        _LOGGER.info('hvac_modes(): ' + str(self._hvac_modes))
        # Return the list of available operation modes.
        return self._hvac_modes

    @property
    def swing_mode(self) -> str | None:
        _LOGGER.info('swing_mode(): ' + str(self._swing_mode))
        # get the current swing mode
        return self._swing_mode

    @property
    def swing_modes(self) -> list[str] | None:
        _LOGGER.info('swing_modes(): ' + str(self._swing_modes))
        # get the list of available swing modes
        return self._swing_modes

    @property
    def swing_horizontal_mode(self) -> str | None:
        if self._horizontal_swing:
            _LOGGER.info('swing_horizontal_mode(): ' + str(self._swing_horizontal_mode))
            # get the current swing horizontal mode
            return self._swing_horizontal_mode
        else:
            return None

    @property
    def swing_horizontal_modes(self) -> list[str] | None:
        _LOGGER.info('swing_horizontal_modes(): ' + str(self._swing_horizontal_modes))
        # get the list of available swing horizontal modes modes
        return self._swing_horizontal_modes

    @property
    def fan_mode(self):
        _LOGGER.info('fan_mode(): ' + str(self._fan_mode))
        # Return the fan mode.
        return self._fan_mode

    @property
    def fan_modes(self):
        _LOGGER.info('fan_list(): ' + str(self._fan_modes))
        # Return the list of available fan modes.
        return self._fan_modes
        
    @property
    def supported_features(self):
        if self._horizontal_swing:
            sf =  SUPPORT_FLAGS | ClimateEntityFeature.SWING_HORIZONTAL_MODE
        else:
            sf = SUPPORT_FLAGS
        _LOGGER.info('supported_features(): ' + str(sf))
        # Return the list of supported features.
        return sf

    @property
    def unique_id(self):
        # Return unique_id
        return self._unique_id

    def set_temperature(self, **kwargs):
        _LOGGER.info('set_temperature(): ' + str(kwargs.get(ATTR_TEMPERATURE)))
        # Set new target temperatures.
        if kwargs.get(ATTR_TEMPERATURE) is not None:
            # do nothing if temperature is none
            if not (self._acOptions['Pow'] == 0):
                # do nothing if HVAC is switched off
                _LOGGER.info('SyncState with SetTem=' + str(kwargs.get(ATTR_TEMPERATURE)))
                self.SyncState({ 'SetTem': int(kwargs.get(ATTR_TEMPERATURE))})
                self.schedule_update_ha_state()

    def set_swing_mode(self, swing_mode: str) -> None:
        _LOGGER.info('Set swing mode(): ' + str(swing_mode))
        # set the swing mode
        if not (self._acOptions['Pow'] == 0):
            # do nothing if HVAC is switched off
            _LOGGER.info('SyncState with SwUpDn=' + str(swing_mode))
            self.SyncState({'SwUpDn': self._swing_modes.index(swing_mode)})
            self.schedule_update_ha_state()

    def set_swing_horizontal_mode(self, swing_horizontal_mode: str) -> None:
        if not (self._acOptions['Pow'] == 0):
            # do nothing if HVAC is switched off
            _LOGGER.info('SyncState with SwingLfRig=' + str(swing_horizontal_mode))
            self.SyncState({'SwingLfRig': self._swing_horizontal_modes.index(swing_horizontal_mode)})
            self.schedule_update_ha_state()

    def set_fan_mode(self, fan):
        _LOGGER.info('set_fan_mode(): ' + str(fan))
        # Set the fan mode.
        if not (self._acOptions['Pow'] == 0):
            if (fan.lower() == 'turbo'):
                _LOGGER.info('Enabling turbo mode')
                self.SyncState({'Tur': 1, 'Quiet': 0})
            elif (fan.lower() == 'quiet'):
                _LOGGER.info('Enabling quiet mode')
                self.SyncState({'Tur': 0, 'Quiet': 1})
            else:
                _LOGGER.info('Setting normal fan mode to ' + str(self._fan_modes.index(fan)))
                self.SyncState({'WdSpd': str(self._fan_modes.index(fan)), 'Tur': 0, 'Quiet': 0})
            self.schedule_update_ha_state()

    def set_hvac_mode(self, hvac_mode):
        _LOGGER.info('set_hvac_mode(): ' + str(hvac_mode))
        # Set new operation mode.
        c = {}
        if (hvac_mode == HVACMode.OFF):
            c.update({'Pow': 0})
            if self._attributes['auto_light'] is True:
                c.update({'Lig': 0})
                if self._has_light_sensor is True and self._attributes['light_sensor'] is STATE_ON:
                    c.update({'LigSen': 1})
        else:
            c.update({'Pow': 1, 'Mod': self.hvac_modes.index(hvac_mode)})
            if self._attributes['auto_light'] is True:
                c.update({'Lig': 1})
                if self._has_light_sensor is True and self._attributes['light_sensor'] is STATE_ON:
                    c.update({'LigSen': 0})
            if self._attributes['auto_xfan'] is True:
                if (hvac_mode == HVACMode.COOL) or (hvac_mode == HVACMode.DRY):
                    c.update({'Blo': 1})   
        self.SyncState(c)
        self.schedule_update_ha_state()

    def turn_on(self): 
        _LOGGER.info('turn_on(): ')
        # Turn on.
        c = {'Pow': 1}
        if self._attributes['auto_light'] is True:
            c.update({'Lig': 1})
            if self._has_light_sensor is True and self._attributes['light_sensor'] is STATE_ON:
                c.update({'LigSen': 0})
        self.SyncState(c)
        self.schedule_update_ha_state()

    def turn_off(self):
        _LOGGER.info('turn_off(): ')
        # Turn off.
        c = {'Pow': 0}
        if self._attributes['auto_light'] is True:
            c.update({'Lig': 0})
            if self._has_light_sensor is True and self._attributes['light_sensor'] is STATE_ON:
                    c.update({'LigSen': 1})
        self.SyncState(c)
        self.schedule_update_ha_state()

    async def async_added_to_hass(self):
        _LOGGER.info('Gree climate device added to hass()')
        await super().async_added_to_hass()
        try:
            state = await self.async_get_last_state()
        except:
            _LOGGER.info('Entity state cannot be restored')
        else:
            _LOGGER.info('Restoring auto_light and auto_xfan state')
            self._attributes['auto_light'] = state.attributes['auto_light']
            self._attributes['auto_xfan'] = state.attributes['auto_xfan']
        self.update()
