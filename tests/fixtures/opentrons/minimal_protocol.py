from opentrons import protocol_api


metadata = {
    "protocolName": "Datalox virtual lifecycle fixture",
    "author": "Datalox",
    "description": "Self-authored protocol with no physical movement.",
    "apiLevel": "2.20",
}


def run(protocol: protocol_api.ProtocolContext) -> None:
    protocol.comment("Datalox virtual lifecycle fixture completed.")
