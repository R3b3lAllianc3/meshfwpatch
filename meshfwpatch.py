import sys

if sys.version_info < (3, 5):
    print(("ERROR: To use {} you need at least Python 3.5.\n" +
           "You are currently using Python {}.{}").format(sys.argv[0], *sys.version_info))
    sys.exit(1)

from intelhex import IntelHex
from mesh.database import MeshDB
import logging
import copy
import uuid
import argparse  
import re

def validate_mesh_version(s):    
    try:
        converted_int = int(s, 10)
        if ((converted_int != 400) and (converted_int != 320)):
            raise argparse.ArgumentTypeError('Mesh SDK version must be 400 or 320!')
        else:
            return converted_int
    except ValueError:
        raise argparse.ArgumentTypeError('Invalid Mesh SDK version specified!')

def validate_device_key(s):
    try:
        #Make sure user specified a string of 32 characters
        if (len(s) != 32):
            raise argparse.ArgumentTypeError('Must be 32 characters long hexadecimal string!')
        else:            
            return int(s, 16).to_bytes(16, byteorder="big", signed=False)
    except ValueError:
        raise argparse.ArgumentTypeError('Invalid device key specified!')

def validate_start_node(s):
    try:
        converted_int = int(s, 10)
        if ((converted_int < 0x0) or (converted_int > 0x3FFF)):
            raise argparse.ArgumentTypeError('Start node value must be a positive number and less than 0x4000!')
        else:
            return converted_int 
    except ValueError:
        raise argparse.ArgumentTypeError('Invalid start node specified!')        

def validate_unicast_address(s):
    try:
        return int(s, 16)
    except ValueError:
        raise argparse.ArgumentTypeError('Invalid unicast address specified!')

def list_db_info(s):
    try:
        db = MeshDB(s)    
        print('');
        for i in db.nodes:            
            print('Node name: {0}'.format(i.name))
            print('Device key: {0}'.format(i.device_key.hex()))
            print('Unicast address: {0}'.format(hex(i.unicast_address)))
            print('');
    except Exception as ex:
        logging.exception("Error parsing JSON file")
    sys.exit(-1)
     
class Hex_File(object):
    """
    This class handles patching the hex file with new device key and unicast address.            
    """    
    def __init__(self, options):
        """
        Initializer function.
        
        Keyword arguments:
        options -- Object created by parser.parse_args() that holds all the parameter values.
        """
        try:
            self.hf_db = MeshDB(options.db_input_file)            
            self.hf_hex_file = IntelHex(options.hex_input_file)
            self.hf_number_of_nodes = len(self.hf_db.nodes)
            self.hf_start_node = options.start_node
            self.hf_mesh_sdk_version = options.mesh_sdk_version
            self.hf_clone_copies = options.clone_copies
            if (self.hf_mesh_sdk_version == 400):
                self.START_OF_FLASH_MANAGER_OFFSET = 0x50
                self.UNICAST_ADDRESS_OFFSET_1 = 0x1C
                self.UNICAST_ADDRESS_OFFSET_2 = 0x4C
            else:
                #Else assuming v3.2.0 of Nordic Mesh SDK
                self.START_OF_FLASH_MANAGER_OFFSET = 0x40
                self.UNICAST_ADDRESS_OFFSET_1 = 0x1C
                self.UNICAST_ADDRESS_OFFSET_2 = 0x3C
            logging.debug('Start node is {0}'.format(self.hf_start_node))
            if self.hf_start_node is not None:
                self.hf_working_node = self.hf_db.nodes[self.hf_start_node]
            else:
                self.hf_working_node = self.hf_db.nodes[(self.hf_number_of_nodes - 1)]
            self.hf_output_hex_fw_name = options.hex_output_file
            self.hf_new_device_key = options.device_key
            #Create new device key, if not specified
            #if self.hf_new_device_key is None:
                #self.hf_new_device_key = uuid.uuid4().int.to_bytes(16, byteorder="big", signed=False)
            #    self.hf_new_device_key = _generate_new_device_key()
            self.hf_new_unicast_addr = options.unicast_address
            self.hf_new_node_name = options.node_name
            self._hf_iteration = 0
        except Exception as ex:
            logging.exception("Initialization error")
    
    def _generate_new_device_key(self):
        return uuid.uuid4().int.to_bytes(16, byteorder="big", signed=False)       
    
    def patch_hex_file(self):
        """
        This function patches the hex file with the new device key and the new unicast address.        
        """
        try:
            logging.debug('Patching for Mesh SDK version {0}'.format(self.hf_mesh_sdk_version))
            #Get the device key from the database file
            self.hf_device_key = self.hf_working_node.device_key
            #Convert hex data to byte string so we can easily find the device key
            self.hf_input_hex_fw_bytestr = self.hf_hex_file.tobinstr()
            #Convert hex data to byte array that will represent the output patched hex file
            self.hf_output_hex_fw_bytearray = self.hf_hex_file.tobinarray()            
            #Find the index where the device key starts
            logging.debug('Looking for device key {0}'.format(self.hf_device_key.hex()))
            self.hf_device_key_index = self.hf_input_hex_fw_bytestr.find(self.hf_device_key)
            if (self.hf_device_key_index == -1):
                logging.info('Device key not found! Are you sure the correct node is specified (--start-node)? ')
                raise ValueError('Device key not found in hex file!  Aborting!')
            logging.info("Device key found at location {0}".format(hex(self.hf_device_key_index)))
            #Sanity check: for the infinitesimally small chance that the device key occurs elsewhere in the hex file naturally!
            #Check for Flash Manager Area signature: https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.meshsdk.v4.0.0%2Fmd_doc_libraries_flash_manager.html
            self.hf_expected_start_of_flash_manager_index = (self.hf_device_key_index - self.START_OF_FLASH_MANAGER_OFFSET)
            #This is where signature should be
            self.hf_flash_manager_sign_found = self.hf_input_hex_fw_bytestr.startswith(bytearray.fromhex('08041010'), (self.hf_expected_start_of_flash_manager_index), (self.hf_expected_start_of_flash_manager_index + 16))
            if (self.hf_flash_manager_sign_found == False):
                logging.info('Flash Area Manager signature not found at expected location {0}'.format(hex(self.hf_expected_start_of_flash_manager_index)))
                raise ValueError('Flash Area Manager signature not found at expected location {0}'.format(hex(self.hf_expected_start_of_flash_manager_index)))
            else:
                logging.info('Flash Area Manager signature found at expected location {0}'.format(hex(self.hf_expected_start_of_flash_manager_index)))                      
            #Get offset for both occurences of device handle which also need to be updated per device
            self.hf_expected_device_uc_addr_index = (self.hf_expected_start_of_flash_manager_index + self.UNICAST_ADDRESS_OFFSET_1)
            self.hf_expected_device_uc_addr_index_second = (self.hf_expected_start_of_flash_manager_index + self.UNICAST_ADDRESS_OFFSET_2)                                    
            #Create new unicast address by reading all existing unicast addresses in the db file, finding the max, and incrementing the largest one by one.
            if self.hf_new_unicast_addr is None:                            
                #Create a list of unicast addresses from the db file
                self.unicast_address_list = []
                for i in self.hf_db.nodes:
                    self.unicast_address_list.append(i.unicast_address)
                #Find highest unicast address and increment by 1 to create new unicast address
                self.next_unicast_address = max(self.unicast_address_list) + 1
                logging.info('Next available unicast address is {0}'.format(hex(self.next_unicast_address)))
                self.hf_new_unicast_addr = self.next_unicast_address

            for x in range(self.hf_clone_copies):
                ####Patch and write the cloned fw
                #Update device unicast address in output bytearray
                self.hf_output_hex_fw_bytearray[self.hf_expected_device_uc_addr_index] = self.hf_new_unicast_addr
                self.hf_output_hex_fw_bytearray[self.hf_expected_device_uc_addr_index_second] = self.hf_new_unicast_addr                
                #Generate new device key only if not specified on command line 
                if (self.hf_new_device_key is None):
                    self.hf_new_device_key = self._generate_new_device_key()
                #Replace key in bytearray with new key
                for i in range(0, 16):                
                    self.hf_output_hex_fw_bytearray[self.hf_device_key_index+i] = self.hf_new_device_key[i]
                #Create output IntelHex object...
                self.hf_output_hex_fw = IntelHex()
                #...and load it up with patched data
                self.hf_output_hex_fw.frombytes(self.hf_output_hex_fw_bytearray)
                #Write out new patched fw file
                #New file name for each clone, except first one
                if (self._hf_iteration == 0):
                    logging.debug('Creating {0}'.format(self.hf_output_hex_fw_name))
                    self.hf_output_hex_fw.write_hex_file(self.hf_output_hex_fw_name)                    
                else:
                    self._hf_output_hex_fw_name_list = re.split('(\W)', self.hf_output_hex_fw_name)
                    self._hf_output_hex_fw_name = self._hf_output_hex_fw_name_list[0] + "_" + str(self._hf_iteration) + "".join(self._hf_output_hex_fw_name_list[1:])
                    logging.debug('Creating {0}'.format(self._hf_output_hex_fw_name))
                    self.hf_output_hex_fw.write_hex_file(self._hf_output_hex_fw_name)
                self._hf_iteration += 1
                ####Done patching and write the cloned fw
                
                ####Update JSON file with new node information
                #Create a new node for the new firmware in the JSON file by shallow copying from the original node in the JSON file
                self.hf_new_node = copy.copy(self.hf_working_node)
                #Update device address and unicast address
                self.hf_new_node.device_key = self.hf_new_device_key.hex()                            
                self.hf_new_node.unicast_address = self.hf_new_unicast_addr
                self.hf_db.nodes.append(self.hf_new_node)
                #Update node name
                if (self.hf_new_node_name is None):
                    self.hf_new_node.name += "_" + str(self.hf_new_unicast_addr)
                else:
                    self.hf_new_node.name = self.hf_new_node_name
                #Store to file
                self.hf_db.store()   
                ####Done updating JSON file with new node information
                
                ####Reinitialize variables for next iteration, if any
                #Reset the device key so new one is generated in next iteration in case multiple clones are requested.
                #This also means if device key is specified on command-line and multiple clones requested then only first 
                #fw clone will have that specified key & the rest of clones will have auto-generated keys.
                self.hf_new_device_key = None   
                #Increment unicast address for next node, if there are more iterations.
                #This also means if unicast address is specified on command-line and multiple clones requested then only first 
                #fw clone will have that specified unicast address & the rest of clones will have unique unicast addresses generated by 
                #incrementing command-line specified node by 1.
                self.hf_new_unicast_addr = self.hf_new_unicast_addr + 1
                #Reset node name to none for next iteration, if there are more iterations
                #This also means if node name is specified on command-line and multiple clones requested then only first 
                #fw clone will have that node name & the rest of clones will have auto-generated node names.
                self.hf_new_node_name = None
                ####Done reinitializing variables for next iteration, if any
        except Exception as ex:
            logging.exception("Hex file patching error")
            
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Nordic Mesh firmware patching script")
    parser.add_argument("--list-info",
                        dest="list_info",
                        metavar="DB_INPUT_FILE",
                        required=False,                                                
                        default=None,
                        type=list_db_info,
                        help="List the device key, unicast address, and node name for each node found in the specified JSON file.  "                                
                                + "If this command is specified, all other commands are ignored.  Useful for informational purposes."
                        )
    parser.add_argument("--hex-input-file",
                        dest="hex_input_file",                        
                        required=True,                        
                        help=("Specify the Intel Hex file to be used as input. "
                              + "Contents will be read from this file and patched. This is the hex file that has been ripped from a provisioned node "
                              + "by nrfjprog.  "
                              + "This file shall NOT be modified."))
    parser.add_argument("--db-input-file",
                        dest="db_input_file",                        
                        required=True,                        
                        help="Specify the JSON file that holds the mesh network state.  "
                            + "This is the full path and filename of the JSON database file from which we will be extracting device key and unicast address from. "
                            + "This file is typically created by PyACI in scripts/interactive_pyaci/database/ directory and has the device key that matches the device key in the firmware.  "
                            + "This file will be MODIFIED to add the new node's information."
                        )
    parser.add_argument("--hex-output-file",
                        dest="hex_output_file",                        
                        required=True,                        
                        help="Specify the name of the patched output file that will be created.  For multiple clones, specify base filename.")
    parser.add_argument("--start-node",
                        dest="start_node",                        
                        required=False,
                        type=validate_start_node,
                        default=None,
                        help="This is the zero-based index of the mesh node in the JSON file which correlates to the input firmware "
                                + "file.  The device key and unicast address specified for this node in the database file "
                                + "will be searched for in the firmware and replaced.  If not specified, the last node in the database file is used.  "
                                + "This value must be specified in base 10."
                        )
    parser.add_argument("--device-key",
                        dest="device_key",                        
                        required=False,
                        type=validate_device_key,
                        metavar="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                        default=None,
                        help="A 32-character hexadecimal value that specifies a device key i.e. '0371592428B84C66F91D3466421C4FC1'.  "
                                + "This value is patched into the generated output firmware for the new node. "
                                + "If not specified, a random value is auto-generated."
                        )  
    parser.add_argument("--unicast-addr",
                        dest="unicast_address",                        
                        required=False,
                        type=validate_unicast_address,
                        metavar="0xyyyy",
                        default=None,
                        help="A 16-bit hexadecimal value that specifies a unicast address.  "
                                + "This value is unique per node.  If specified, ensure it is valid as uniqueness is not ascertained by this script.  "
                                + "If not specified, a unique value is auto-generated by incrementing the --start-node value (see help description for that flag)."
                        )  
    parser.add_argument("--node-name",
                        dest="node_name",                        
                        required=False,                                                
                        default=None,
                        help="Specify the new node's name to be recorded in the JSON file.  "                                
                                + "If not specified, a unique name is auto-generated."
                        )
    parser.add_argument("--mesh-sdk-version",
                        dest="mesh_sdk_version",   
                        default=400,
                        required=False,
                        metavar="400 or 320",                        
                        type=validate_mesh_version,                        
                        help="Specify the Nordic Mesh SDK version.  Only v4.0.0 and v3.2.0 have been tested.  Default is Nordic Mesh SDK v4.0.0.  Due to subtle differences in generated code, "                                
                                + "it's necessary to discern between the Nordic Mesh SDK versions.  If not specified, v4.0.0 is assumed."
                        )
                        
    parser.add_argument("--clone-copies",
                        dest="clone_copies",   
                        default=1,
                        required=False,
                        type=int,
                        metavar="Number of firmware copies to create",
                        help="Specify the number of copies to clone from the original firmware."
                        #TODO: validate this as a positive number on the command line
                        )
                        
    parser.add_argument("-l", "--log-level",
                        dest="log_level",
                        type=int,
                        required=False,
                        default=3,
                        help=("Set default logging level: "
                              + "1=Errors only, 2=Warnings, 3=Info, 4=Debug")
                        )
    options = parser.parse_args()

    if options.log_level == 1:
        options.log_level = logging.ERROR
    elif options.log_level == 2:
        options.log_level = logging.WARNING
    elif options.log_level == 3:
        options.log_level = logging.INFO
    else:
        options.log_level = logging.DEBUG
   
    logging.basicConfig(level=options.log_level)
   
    hx = Hex_File(options)
    hx.patch_hex_file()
    
