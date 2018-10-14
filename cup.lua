
cup = Proto("CUP",  "Chris' UDP Protocol")

function cup.dissector(buffer, pktinfo, tree)

  local pktlength = buffer:len()

  pktinfo.cols.protocol = cup.name

  local subtree = tree:add(cup,buffer())

  local tlvs = 0
  local offset = 5 -- ignore the first 5 bytes right away
  while offset < pktlength do
    local type = buffer(offset,1):uint()
    local length = buffer(offset+1,1):uint()
    local value = buffer(offset+2,length-2):string()
    -- now we have type, length and value, let's print them
    local tlvtree = subtree:add(cup, buffer(offset,length), "TLV", tlvs)
    tlvtree:add(buffer(offset+0,1),"Type:",type)
    tlvtree:add(buffer(offset+1,1),"Length:",length)
    tlvtree:add(buffer(offset+2,length-2),"Value:",value)

    tlvs = tlvs + 1
    offset = offset + length
  end

  if tlvs == 1 then
    pktinfo.cols.info = "CUP, 1 TLV"
  else
    pktinfo.cols.info = "CUP, " .. tlvs .. " TLVs"
  end
  
  return
end

DissectorTable.get("udp.port"):add("11234", cup)


