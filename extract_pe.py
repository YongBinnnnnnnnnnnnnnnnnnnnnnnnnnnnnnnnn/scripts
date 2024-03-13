#!/bin/python3
import pefile
import sys

with open(sys.argv[1], "rb+") as f:
  data = f.read()
  
offset = 0
while True:
  try:
    offset = data.index(b'MZ', offset)
  except:
    break

  try:
    pe = pefile.PE(data=data[offset:])
    
    print(offset)
    print(pe)
    #print(pe.get_overlay_data_start_offset())
  except Exception as e:
    print(offset, e)
    print(data[offset:offset + 64])
  
  offset = offset + 2


