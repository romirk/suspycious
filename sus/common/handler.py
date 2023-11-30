import asyncio
import logging
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.ciphers import AEADDecryptionContext, AEADEncryptionContext

from sus.common.util import ConnectionID, ConnectionState, now


class BaseHandler(ABC):
    __logger: logging.Logger

    __inc_dec: AEADDecryptionContext
    __out_enc: AEADEncryptionContext
    __inc_mac: AEADDecryptionContext
    __out_mac: AEADEncryptionContext

    __transport: asyncio.DatagramTransport

    __app_id: bytes
    __con_id: ConnectionID

    __last_seen: float
    __pid: int

    __pending_message_buffer: bytes
    __pending_message_length: int

    @abstractmethod
    def __initial(self, data: bytes):
        """
        Handles initial packets.
        :param data: packet data
        """
        raise NotImplementedError

    @abstractmethod
    def __handshake(self, data: bytes):
        """
        Handles handshake packets.
        :param data: packet data
        """
        raise NotImplementedError

    @abstractmethod
    def __connected(self, data: bytes):
        """
        Handles connected packets.
        :param data: packet data
        """
        raise NotImplementedError

    @abstractmethod
    def __disconnected(self, data: bytes):
        """
        Handles disconnected packets.
        :param data: packet data
        """
        raise NotImplementedError

    @abstractmethod
    def __error(self, data: bytes):
        """
        Handles error packets.
        :param data: packet data
        """
        raise NotImplementedError

    def __reform_messages(self, data: bytes) -> list[bytes]:
        buffer = self.__pending_message_buffer + data
        pending_length = self.__pending_message_length
        messages = []
        # self.__logger.debug(f"buffer: {buffer.hex()}")
        while len(buffer) >= pending_length:
            if pending_length == 0:
                if len(buffer) < 4:
                    break
                pending_length = int.from_bytes(buffer[:4], "little")
                buffer = buffer[4:]
            else:
                messages.append(bytes(buffer[:pending_length]))
                buffer = buffer[pending_length:]
                pending_length = 0
        self.__pending_message_buffer = buffer
        self.__pending_message_length = pending_length
        # self.__logger.debug(f"pending: {pending_length}")
        return messages

    def __verify_and_decrypt(self, data: bytes) -> bytes | None:
        try:
            p_id = int.from_bytes(data[:8], "little")
            if p_id > self.__pid + self.max_packets or p_id < self.__pid:
                self.__logger.error(f"Packet {p_id} dropped")
                self.__logger.debug(f"Current packet ID: {self.__pid}")
                return None
            key = self.__incoming_keys[p_id - self.__pid]
            payload = data[8:-16]
            tag = data[-16:]
            poly1305.Poly1305.verify_tag(key, data[:8] + payload, tag)
        except InvalidSignature:
            self.__logger.error("Invalid signature")
            return None

        match p_id:
            case 0:
                # special case for first packet
                payload = payload[32:]
                self.__logger.debug(f"--- {trail_off(payload.hex())}")
                self.__pid = 1
                message_bytes = self.__inc_dec.update(payload)

                self.__incoming_keys.popleft()
                self.__incoming_keys.append(self.__inc_mac.update(b"\x00" * 32))
                return message_bytes
            case self.__pid:
                self.__logger.debug(f"--- {trail_off(payload.hex())}")

                # packet has already been verified
                _ = self.__incoming_keys.popleft()
                self.__incoming_keys.append(self.__inc_mac.update(b"\x00" * 32))
                self.__pid += 1
                message_bytes = self.__inc_dec.update(payload)
                buffer = bytearray(message_bytes)

                while self.__incoming_packets[0]:
                    packet = self.__incoming_packets.popleft()
                    _ = self.__incoming_keys.popleft()
                    p_id = int.from_bytes(packet[:8], "little")
                    self.__logger.debug(f"expected pid: {self.__pid} got {p_id}")
                    assert p_id == self.__pid
                    self.__incoming_keys.append(self.__inc_mac.update(b"\x00" * 32))
                    self.__incoming_packets.append(b"")
                    self.__pid += 1
                    payload = packet[8:-16]
                    message_bytes = self.__inc_dec.update(payload)
                    buffer.extend(message_bytes)

                return bytes(buffer)

            case _:
                self.__incoming_keys.insert(p_id - self.__pid, self.__inc_mac.update(payload))
                self.__incoming_packets.insert(p_id - self.__pid, data)
                return None

    def __encrypt_and_tag(self, data: bytes) -> list[bytes]:
        message_bytes = len(data).to_bytes(4, "little") + data
        padded_message_bytes = message_bytes  # + b"\x00" * (
        # packet_length - ((len(message_bytes)) % packet_length))

        ciphertext = self.__out_enc.update(padded_message_bytes)
        self.__logger.debug(f"--- {trail_off(ciphertext.hex())}")

        payloads = self.__split_message(ciphertext)

        packets = []
        for payload in payloads:
            key = self.__out_mac.update(b"\x00" * 32)
            p_id = self.__pid.to_bytes(8, "little")
            frame = p_id + payload
            tag = poly1305.Poly1305.generate_tag(key, frame)
            packets.append(frame + tag)
            self.__outgoing_packet_id += 1
        return packets

    def handle(self, data: bytes):
        """
        Handles incoming packets.
        :param data: packet data
        """
        self.__last_seen = now()

        match self.__state:
            case ConnectionState.INITIAL:
                self.__initial(data)
            case ConnectionState.HANDSHAKE:
                self.__handshake(data)
            case ConnectionState.CONNECTED:
                self.__connected(data)
            case ConnectionState.DISCONNECTED:
                self.__disconnected(data)
            case ConnectionState.ERROR:
                self.__error(data)

    def __flush(self):
        """
        Flushes the outgoing buffer, sending all pending messages.
        Sends multiple packets if necessary. Sends an empty packet if there is no data to send.
        """
        packets = self.__encrypt_and_tag(self.__outgoing_buffer or b"\x00")
        self.__logger.debug(f"Sending {len(self.__outgoing_buffer)} bytes in {len(packets)} packets")
        for packet in packets:
            self.__transport.sendto(packet, self.__addr)
        self.__outgoing_buffer.clear()

    def __send_later(self, data: bytes):
        """
        Schedule a message to be sent to the client.
        :param data: data to send
        """
        if self.__state not in (ConnectionState.CONNECTED, ConnectionState.HANDSHAKE):
            return
        self.__logger.debug(f"<<< {trail_off(data.decode('utf-8'))}")
        self.__outgoing_buffer.extend(data)

    def __send_now(self, data: bytes):
        self.__outgoing_buffer.extend(data)
        self.__flush()

    def add_message_handler(self, handler: MessageHandler):
        """
        Adds a message handler. This handler will be called when a message is received.
        :param handler: Awaitable handler function
        """
        self.__message_handlers.add(handler)

    def disconnect(self):
        """
        Disconnects the client.
        """
        self.__state = ConnectionState.DISCONNECTED
        self.__logger.info("Disconnected")
        self.__send_now(b"\x01")
        self.__send_loop_task.cancel()
