# SDN Firewall

A stateless Layer 4 SDN firewall implemented in OpenFlow.

Since Ryu is no longer maintained and there are difficulties installing it with newer software, the open-source fork OS-Ken is used.

## Features
- Stateless Layer 4 packet filtering
- OpenFlow-based traffic control
- Easy integration with Mininet for testing

## Setup
### 1. Clone the repository:
   ```sh
    git clone https://github.com/DLemming/sdn-firewall.git
    cd sdn-firewall
   ```
### 2. Install dependencies:
Ensure you have ```uv``` installed. If not, installations instructions can be found [here](https://docs.astral.sh/uv/getting-started/installation/#standalone-installer).

Then set up the virtual environment and install dependencies:
   ```sh
   uv venv
   uv sync
   ```

Alternatively, you can install dependencies using pip:
```sh
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Usage
### 1. Start the SDN-Controller

```sh
python3 src/Firewall.py
```

### 2. Start the Mininet Environment
```sh
sudo python3 src/OpenFlowTopo.py
```
This will initialize the Mininet topology with OpenFlow support.

## Notes
- Ensure that Open vSwitch (OVS) is installed and running.
- Run the scripts with appropriate permissions (e.g., sudo for Mininet).
- Modify the firewall rules in Firewall.py to customize filtering behavior.

## License
This project is open-source and available under the MIT License.