from intelhex import IntelHex
from mesh.database import MeshDB
import sys
import logging
import copy
import uuid
import argparse  

def validate_device_key(s):
    try:
        #Make sure user specified a string of 32 characters
        if (len(s) != 32):
            raise argparse.ArgumentTypeError('Must be 32 characters long hexadecimal string!')
        int(s, 16)
    except Exception as ex:
        raise argparse.ArgumentTypeError('Invalid device key specified!')

def validate_start_node(s):
    try:
        converted_int = int(s, 10)
        if ((converted_int < 0x0) or (converted_int > 0x3FFF)):
            raise argparse.ArgumentTypeError('Start node value must be a positive number and less than 0x4000!')
    except Exception as ex:
        raise argparse.ArgumentTypeError('Invalid start node specified!')        

def validate_unicast_address(s):
    try:
        converted_int = int(s, 16)
    except Exception as ex:
        raise argparse.ArgumentTypeError('Invalid unicast address specified!')
     
class Hex_File(object):
    """
    This class handles patching the hex file with new device key and unicast address.            
    """
    #def __init__(self, hex_file, db_file, start_node=None):
    def __init__(self, options, start_node=None):
        """
        Initializer function.
        
        Keyword arguments:
        hex_file   -- This is the full path and filename of the hex file that has been ripped from a provisioned node.
        db_file    -- This is the full path and filename of the JSON database file from which we will be extracting device key and unicast address from.
                      This file is typically created by PyACI in scripts/interactive_pyaci/database/ directory and has the device key that matches the device key in the firmware.
        start_node -- If specified then this is the node within db_file from which to get device key from.  This number is a zero-based index.
                      If specified as None, the last node in db_file is used to obtain the device key.
        """
        try:
            #self.hf_db = MeshDB(db_file)
            self.hf_db = MeshDB(options.db_input_file)
            #self.hf_hex_file = IntelHex(hex_file)
            self.hf_hex_file = IntelHex(options.hex_input_file)
            self.hf_number_of_nodes = len(self.hf_db.nodes)
            if start_node is not None:
                self.hf_working_node = self.hf_db.nodes[start_node]
            else:
                self.hf_working_node = self.hf_db.nodes[(self.hf_number_of_nodes - 1)]           
        except Exception as ex:
            logging.exception("Initialization error")
                        
    def patch_hex_file(self, output_hex_file, new_device_key=None, new_unicast_addr=None):
        """
        This function patches the hex file with the new device key and the new unicast address.
        
        Keyword arguments:
        new_device_key     -- If specified then it's a 16-byte hex string i.e. '0371592428B84C66F91D3466421C4FC1'.
                              If specified as None, then new device key will be generated automatically.
        new_unicast_addr   -- If specified then it's specified as a 16-bit hex value i.e. 0x0011
                              If specified as None, then new unicast address will be generated automatically.        
        """
        try:
            #Get the device key from the database file
            self.hf_device_key = self.hf_working_node.device_key
            #Convert hex data to byte string so we can easily find the device key
            self.hf_input_hex_fw_bytestr = self.hf_hex_file.tobinstr()
            #Convert hex data to byte array that will represent the output patched hex file
            self.hf_output_hex_fw_bytearray = self.hf_hex_file.tobinarray()
            #Find the index where the device key starts
            self.hf_device_key_index = self.hf_input_hex_fw_bytestr.find(self.hf_device_key)
            if (self.hf_device_key_index == -1):
                logging.info('Device key not found! Are you sure the correct node is specified?')
                raise ValueError('Device key not found in hex file!  Aborting!')
            logging.info("Device key found at location {0}".format(hex(self.hf_device_key_index)))
            #Sanity check!
            #Check for Flash Manager Area signature: https://infocenter.nordicsemi.com/topic/com.nordic.infocenter.meshsdk.v3.2.0/md_doc_libraries_flash_manager.html?cp=5_2_2_0
            self.hf_expected_start_of_flash_manager_index = (self.hf_device_key_index - 64)
            #This is where signature should be
            self.hf_flash_manager_sign_found = self.hf_input_hex_fw_bytestr.startswith(bytearray.fromhex('08041010'), (self.hf_expected_start_of_flash_manager_index), (self.hf_expected_start_of_flash_manager_index + 16))
            if (self.hf_flash_manager_sign_found == False):
                logging.info('Flash Area Manager signature not found at expected location {0}'.format(hex(self.hf_expected_start_of_flash_manager_index)))
                raise ValueError('Flash Area Manager signature not found at expected location {0}'.format(hex(self.hf_expected_start_of_flash_manager_index)))
            else:
                logging.info('Flash Area Manager signature found at expected location {0}'.format(hex(self.hf_expected_start_of_flash_manager_index)))   
            #Create new device key
            if new_device_key is None:
                self.hf_new_device_key = uuid.uuid4()
            else:
                self.hf_new_device_key = new_device_key #TODO: validate new_device_key is valid                              
            #Get offset for both occurences of device handle which also needs to be updated per device
            self.hf_expected_device_uc_addr_index = (self.hf_expected_start_of_flash_manager_index + 28)
            self.hf_expected_device_uc_addr_index_second = (self.hf_expected_start_of_flash_manager_index + 28 + 32)                                    
            #Create new unicast address by reading all existing unicast addresses in the db file, finding the max, and incrementing the largest one by one.
            if new_unicast_addr is None:                            
                #Create a list of unicast addresses from the db file
                self.unicast_address_list = []
                for i in self.hf_db.nodes:
                    self.unicast_address_list.append(i.unicast_address)
                #Find highest unicast address and increment by 1 to create new unicast address
                self.next_unicast_address = max(self.unicast_address_list) + 1
                logging.info('Next available unicast address is {0}'.format(hex(self.next_unicast_address)))
                self.hf_new_unicast_addr = self.next_unicast_address
            else:
                self.hf_new_unicast_addr = new_unicast_addr #TODO: validate new_unicast_addr is valid                              
            #Update device unicast address in output bytearray
            self.hf_output_hex_fw_bytearray[self.hf_expected_device_uc_addr_index] = self.hf_new_unicast_addr
            self.hf_output_hex_fw_bytearray[self.hf_expected_device_uc_addr_index_second] = self.hf_new_unicast_addr                       
            #Replace key in bytearray with new key
            for i in range(0, 16):
                self.hf_output_hex_fw_bytearray[self.hf_device_key_index+i] = self.hf_new_device_key.bytes[i]                      
            #Create output IntelHex object
            self.hf_output_hex_fw = IntelHex()
            #Load it up with patched data
            self.hf_output_hex_fw.frombytes(self.hf_output_hex_fw_bytearray)
            #Write out new patched fw file
            self.hf_output_hex_fw.write_hex_file(output_hex_file)
            #Create a new node for the new firmware            
            #Shallow copy from the original node
            self.hf_new_node = copy.copy(self.hf_working_node)
            #Update device address and unicast address
            self.hf_new_node.device_key = self.hf_new_device_key.hex
            self.hf_new_node.unicast_address = self.hf_new_unicast_addr
            self.hf_db.nodes.append(self.hf_new_node)
            #Update node name
            self.hf_new_node.name += "_" + str(self.hf_new_unicast_addr)
            #Store to file
            self.hf_db.store()           
        except Exception as ex:
            logging.exception("Hex file patching error")
            
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Nordic Mesh firmware patching script")
    parser.add_argument("--hex-input-file",
                        dest="hex_input_file",                        
                        required=True,                        
                        help=("Specify the Intel Hex file to be used as input. "
                              + "Contents will be read from this file and patched. "
                              + "This file will NOT be modified."))
    parser.add_argument("--db-input-file",
                        dest="db_input_file",
                        required=True,                        
                        help="Specify the JSON file that holds the mesh network state.")
    parser.add_argument("--hex-output-file",
                        dest="hex_output_file",                        
                        required=True,                        
                        help="Specify the name of the patched output file that will be created.")
    parser.add_argument("--start-node",
                        dest="start_node",                        
                        required=False,
                        type=validate_start_node,                        
                        help="This is the zero-based index of the mesh node in the JSON file which correlates to the input firmware "
                                + "file.  The device key and unicast address specified for this node in the database file "
                                + "will be searched for in the firmware and replaced.  If not specified, the last node in the database file is used.  "
                                + "This value must be specified in base 10.")
    parser.add_argument("--device-key",
                        dest="device_key",                        
                        required=False,
                        type=validate_device_key,
                        metavar="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                        help="A 32-character hexadecimal value that specifies a device key.  "
                                + "If not specified, a random value is auto-generated.  ")  
    parser.add_argument("--unicast-addr",
                        dest="unicast_address",                        
                        required=False,
                        type=validate_unicast_address,
                        metavar="0xyyyy",
                        help="A 16-bit hexadecimal value that specifies a unicast address.  "
                                + "This value is unique per node.  If specified, ensure it is valid as uniqueness is not ascertained by this script.  "
                                + "If not specified, a unique value is auto-generated.  ")  
    parser.add_argument("-l", "--log-level",
                        dest="log_level",
                        type=int,
                        required=False,
                        default=3,
                        help=("Set default logging level: "
                              + "1=Errors only, 2=Warnings, 3=Info, 4=Debug"))
    options = parser.parse_args()

    if options.log_level == 1:
        options.log_level = logging.ERROR
    elif options.log_level == 2:
        options.log_level = logging.WARNING
    elif options.log_level == 3:
        options.log_level = logging.INFO
    else:
        options.log_level = logging.DEBUG
   
    hx = Hex_File(options)
    
