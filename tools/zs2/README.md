**README** please:

- This is a tmp backup of the latest zs2 that was originally migrated to avledet github.
- I will eventually migrate this back over to it with the latest 1.0.20 changes

As of now, this is the latest version of the tool.

# AvlWireshark

Wireshark Lua Dissector for Valheim over TCP

<img width="961" height="441" alt="image" src="https://github.com/user-attachments/assets/b9a24732-9059-4db5-a7e2-0a6b22d568ee" />

## Installation

- Open the plugins folder within Wireshark `Help -> About Wireshark -> Folders -> Personal Lua Plugins (Lua scripts)`
- Extract folder `zsocket2` into plugins folder
- Restart Wireshark
- TCP port 2456 will be automatically dissected

## Usage

- Start the Wireshark capture before all Valheim TCP connections to avoid cut-offs
- To efficiently capture only TCP port 2456 packets, open the interface (`any` on Linux) with capture filter `tcp port 2456`
  - Please note this is completely different from display filtering
  - See https://wiki.wireshark.org/CaptureFilters

## Filters

- Ignore noisy packets (frequent):
    - `zs2 and !(zs2.zdodata.id.id) and !(zs2.msg_type==0) and !(zs2.routedrpc.setevent.name == "") and !(zs2.nettime)`
- Filter to only zdodata:
    - `zs2 and zs2.zdodata.id.id`
- Filter packets only from server:
    - `tcp.srcport == 2456`

## Limitations

- ZDOData vars are currently not added as a field
    - Support for this is planned in the future (ou can see some code already worked on, but temporarily scrapped in the ZDOData generator)
    - I fleshed out more of this dissector while investigating an avl bug related to dungeon generation; you can see ZDOData is a lot more complicated than the other fields because of this.

## TODO
- Add expert info / inspector for anomalies