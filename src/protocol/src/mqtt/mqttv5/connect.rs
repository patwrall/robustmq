// Copyright 2023 RobustMQ Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

pub fn write(
    connect: &Connect,
    properties: &Option<ConnectProperties>,
    will: &Option<LastWill>,
    will_properties: &Option<LastWillProperties>,
    l: &Option<Login>,
    buffer: &mut BytesMut,
) -> Result<usize, Error> {
    let len = {
        let mut len = 2 + "MQTT".len()  // protocol name
                        + 1             // protocol version(v5)
                        + 1             // connect flags
                        + 2; // keep alive

        if let Some(p) = properties {
            let properties_len = properties::len(p);
            let properties_len_len = len_len(properties_len);
            len += properties_len_len + properties_len;
        } else {
            // just 1 byte representing 0 len
            len += 1;
        }

        len += 2 + connect.client_id.len();

        // last will len
        if let Some(w) = will {
            len += will::len(w, will_properties);
        }

        // username and password len
        if let Some(l) = l {
            len += login::len(l)
        }

        len
    };

    buffer.put_u8(0b0001_0000);
    let count = write_remaining_length(buffer, len)?;
    write_mqtt_string(buffer, "MQTT");

    buffer.put_u8(0x05); // protocol version v5
    let flags_index = 1 + count + 2 + 4 + 1;

    let mut connect_flags = 0;
    if connect.clean_session {
        connect_flags |= 0x02;
    }

    buffer.put_u8(connect_flags);
    buffer.put_u16(connect.keep_alive);

    match properties {
        Some(p) => properties::write(p, buffer)?,
        None => {
            write_remaining_length(buffer, 0)?;
        }
    };

    write_mqtt_string(buffer, &connect.client_id);

    if let Some(w) = will {
        connect_flags |= will::write(w, will_properties, buffer)?;
    }

    if let Some(l) = l {
        connect_flags |= login::write(l, buffer);
    }

    // update connect flags
    buffer[flags_index] = connect_flags;
    Ok(len)
}

pub fn read(fixed_header: FixedHeader, mut bytes: Bytes) -> Result<ConnectReadOutcome, Error> {
    let variable_header_index = fixed_header.fixed_header_len;
    bytes.advance(variable_header_index);

    // variable header
    let protocol_name = read_mqtt_string(&mut bytes)?;
    let protocol_level = read_u8(&mut bytes)?;
    if protocol_name != "MQTT" {
        return Err(Error::InvalidProtocol);
    }
    if protocol_level != 5 {
        return Err(Error::InvalidProtocolLevel(protocol_level));
    }

    let connect_flags = read_u8(&mut bytes)?;
    let clean_session = (connect_flags & 0b10) != 0;
    let keep_alive = read_u16(&mut bytes)?;

    let properties = properties::read(&mut bytes)?;
    let client_id = read_mqtt_string(&mut bytes)?;
    let (will, willproperties) = will::read(connect_flags, &mut bytes)?;
    let login = login::read(connect_flags, &mut bytes)?;

    let connect = Connect {
        keep_alive,
        client_id,
        clean_session,
    };

    Ok(ConnectReadOutcome {
        protocol_version: protocol_level,
        connect,
        properties,
        last_will: will,
        last_will_properties: willproperties,
        login,
    })
}

pub mod properties {
    use super::*;

    pub fn read(bytes: &mut Bytes) -> Result<Option<ConnectProperties>, Error> {
        let mut session_expiry_interval = None;
        let mut receive_maximum = None;
        let mut max_packet_size = None;
        let mut topic_alias_max = None;
        let mut request_response_info = None;
        let mut request_problem_info = None;
        let mut user_properties = Vec::new();
        let mut authentication_method = None;
        let mut authentication_data = None;

        let (properties_len_len, properties_len) = length(bytes.iter())?;
        bytes.advance(properties_len_len);
        if properties_len == 0 {
            return Ok(None);
        }

        let mut cursor = 0;
        // read until cursor reaches property length. properties_len = 0 will skip this loop.
        while cursor < properties_len {
            let prop = read_u8(bytes)?;
            cursor += 1;
            match property(prop)? {
                PropertyType::SessionExpiryInterval => {
                    session_expiry_interval = Some(read_u32(bytes)?);
                    cursor += 4;
                }
                PropertyType::ReceiveMaximum => {
                    receive_maximum = Some(read_u16(bytes)?);
                    cursor += 2;
                }
                PropertyType::MaximumPacketSize => {
                    max_packet_size = Some(read_u32(bytes)?);
                    cursor += 4;
                }
                PropertyType::TopicAliasMaximum => {
                    topic_alias_max = Some(read_u16(bytes)?);
                    cursor += 2;
                }
                PropertyType::RequestResponseInformation => {
                    request_response_info = Some(read_u8(bytes)?);
                    cursor += 1;
                }
                PropertyType::RequestProblemInformation => {
                    request_problem_info = Some(read_u8(bytes)?);
                    cursor += 1;
                }
                PropertyType::UserProperty => {
                    let key = read_mqtt_string(bytes)?;
                    let value = read_mqtt_string(bytes)?;
                    cursor += 2 + key.len() + 2 + value.len();
                    user_properties.push((key, value));
                }
                PropertyType::AuthenticationMethod => {
                    let method = read_mqtt_string(bytes)?;
                    cursor += 2 + method.len();
                    authentication_method = Some(method);
                }
                PropertyType::AuthenticationData => {
                    let data = read_mqtt_bytes(bytes)?;
                    cursor += 2 + data.len();
                    authentication_data = Some(data);
                }
                _ => return Err(Error::InvalidPropertyType(prop)),
            }
        }

        Ok(Some(ConnectProperties {
            session_expiry_interval,
            receive_maximum,
            max_packet_size,
            topic_alias_max,
            request_response_info,
            request_problem_info,
            user_properties,
            authentication_method,
            authentication_data,
        }))
    }

    pub fn write(properties: &ConnectProperties, buffer: &mut BytesMut) -> Result<(), Error> {
        let len = len(properties);
        write_remaining_length(buffer, len)?;

        if let Some(session_expiry_interval) = properties.session_expiry_interval {
            buffer.put_u8(PropertyType::SessionExpiryInterval as u8);
            buffer.put_u32(session_expiry_interval);
        }

        if let Some(receive_maximum) = properties.receive_maximum {
            buffer.put_u8(PropertyType::ReceiveMaximum as u8);
            buffer.put_u16(receive_maximum);
        }

        if let Some(max_packet_size) = properties.max_packet_size {
            buffer.put_u8(PropertyType::MaximumPacketSize as u8);
            buffer.put_u32(max_packet_size);
        }

        if let Some(topic_alias_max) = properties.topic_alias_max {
            buffer.put_u8(PropertyType::TopicAliasMaximum as u8);
            buffer.put_u16(topic_alias_max);
        }

        if let Some(request_response_info) = properties.request_response_info {
            buffer.put_u8(PropertyType::RequestResponseInformation as u8);
            buffer.put_u8(request_response_info);
        }

        if let Some(request_problem_info) = properties.request_problem_info {
            buffer.put_u8(PropertyType::RequestProblemInformation as u8);
            buffer.put_u8(request_problem_info);
        }

        for (key, value) in properties.user_properties.iter() {
            buffer.put_u8(PropertyType::UserProperty as u8);
            write_mqtt_string(buffer, key);
            write_mqtt_string(buffer, value);
        }

        if let Some(authentication_method) = &properties.authentication_method {
            buffer.put_u8(PropertyType::AuthenticationMethod as u8);
            write_mqtt_string(buffer, authentication_method);
        }

        if let Some(authentication_data) = &properties.authentication_data {
            buffer.put_u8(PropertyType::AuthenticationData as u8);
            write_mqtt_bytes(buffer, authentication_data);
        }

        Ok(())
    }

    pub fn len(properties: &ConnectProperties) -> usize {
        let mut len = 0;

        if properties.session_expiry_interval.is_some() {
            len += 1 + 4;
        }

        if properties.receive_maximum.is_some() {
            len += 1 + 2;
        }

        if properties.max_packet_size.is_some() {
            len += 1 + 4;
        }

        if properties.topic_alias_max.is_some() {
            len += 1 + 2;
        }

        if properties.request_response_info.is_some() {
            len += 1 + 1;
        }

        if properties.request_problem_info.is_some() {
            len += 1 + 1;
        }

        for (key, value) in properties.user_properties.iter() {
            len += 1 + 2 + key.len() + 2 + value.len();
        }

        if let Some(authentication_method) = &properties.authentication_method {
            len += 1 + 2 + authentication_method.len();
        }

        if let Some(authentication_data) = &properties.authentication_data {
            len += 1 + 2 + authentication_data.len();
        }

        len
    }
}
pub mod will {
    use super::*;

    pub fn len(will: &LastWill, properties: &Option<LastWillProperties>) -> usize {
        let mut len = 0;

        if let Some(p) = properties {
            let properties_len = willproperties::len(p);
            let properties_len_len = len_len(properties_len);
            len += properties_len_len + properties_len;
        } else {
            // just 1 byte representing 0 len
            len += 1;
        }

        len += 2 + will.topic.len() + 2 + will.message.len();
        len
    }

    pub fn read(
        connect_flags: u8,
        bytes: &mut Bytes,
    ) -> Result<(Option<LastWill>, Option<LastWillProperties>), Error> {
        let o = match connect_flags & 0b100 {
            0 if (connect_flags & 0b0011_1000) != 0 => {
                return Err(Error::IncorrectPacketFormat);
            }
            0 => (None, None),
            _ => {
                // Properties in variable header
                let properties = willproperties::read(bytes)?;

                let will_topic = read_mqtt_bytes(bytes)?;
                let will_message = read_mqtt_bytes(bytes)?;
                let qos_num = (connect_flags & 0b11000) >> 3;
                let will_qos = qos(qos_num).ok_or(Error::InvalidQoS(qos_num))?;
                let will = Some(LastWill {
                    topic: will_topic,
                    message: will_message,
                    qos: will_qos,
                    retain: (connect_flags & 0b0010_0000) != 0,
                });

                (will, properties)
            }
        };

        Ok(o)
    }

    pub fn write(
        will: &LastWill,
        properties: &Option<LastWillProperties>,
        buffer: &mut BytesMut,
    ) -> Result<u8, Error> {
        let mut connect_flags = 0;

        connect_flags |= 0x04 | ((will.qos as u8) << 3);
        if will.retain {
            connect_flags |= 0x20;
        }

        if let Some(p) = properties {
            willproperties::write(p, buffer)?;
        } else {
            write_remaining_length(buffer, 0)?;
        }

        write_mqtt_bytes(buffer, &will.topic);
        write_mqtt_bytes(buffer, &will.message);
        Ok(connect_flags)
    }
}

mod willproperties {
    use super::*;

    pub fn len(properties: &LastWillProperties) -> usize {
        let mut len = 0;

        if properties.delay_interval.is_some() {
            len += 1 + 4;
        }

        if properties.payload_format_indicator.is_some() {
            len += 1 + 1;
        }

        if properties.message_expiry_interval.is_some() {
            len += 1 + 4;
        }

        if let Some(content_type_value) = &properties.content_type {
            len += 1 + 2 + content_type_value.len()
        }

        if let Some(topic) = &properties.response_topic {
            len += 1 + 2 + topic.len()
        }

        if let Some(data) = &properties.correlation_data {
            len += 1 + 2 + data.len()
        }

        for (key, value) in properties.user_properties.iter() {
            len += 1 + 2 + key.len() + 2 + value.len();
        }

        len
    }

    pub fn read(bytes: &mut Bytes) -> Result<Option<LastWillProperties>, Error> {
        let mut delay_interval = None;
        let mut payload_format_indicator = None;
        let mut message_expiry_interval = None;
        let mut content_type = None;
        let mut response_topic = None;
        let mut correlation_data = None;
        let mut user_properties = Vec::new();

        let (properties_len_len, properties_len) = length(bytes.iter())?;
        bytes.advance(properties_len_len);
        if properties_len == 0 {
            return Ok(None);
        }

        let mut cursor = 0;
        // read until cursor reaches property length. properties_len = 0 will skip this loop
        while cursor < properties_len {
            let prop = read_u8(bytes)?;
            cursor += 1;

            match property(prop)? {
                PropertyType::WillDelayInterval => {
                    delay_interval = Some(read_u32(bytes)?);
                    cursor += 4;
                }
                PropertyType::PayloadFormatIndicator => {
                    payload_format_indicator = Some(read_u8(bytes)?);
                    cursor += 1;
                }
                PropertyType::MessageExpiryInterval => {
                    message_expiry_interval = Some(read_u32(bytes)?);
                    cursor += 4;
                }
                PropertyType::ContentType => {
                    let content_type_value = read_mqtt_string(bytes)?;
                    cursor += 2 + content_type_value.len();
                    content_type = Some(content_type_value);
                }
                PropertyType::ResponseTopic => {
                    let topic = read_mqtt_string(bytes)?;
                    cursor += 2 + topic.len();
                    response_topic = Some(topic);
                }
                PropertyType::CorrelationData => {
                    let data = read_mqtt_bytes(bytes)?;
                    cursor += 2 + data.len();
                    correlation_data = Some(data);
                }
                PropertyType::UserProperty => {
                    let key = read_mqtt_string(bytes)?;
                    let value = read_mqtt_string(bytes)?;
                    cursor += 2 + key.len() + 2 + value.len();
                    user_properties.push((key, value));
                }
                _ => return Err(Error::InvalidPropertyType(prop)),
            }
        }

        Ok(Some(LastWillProperties {
            delay_interval,
            payload_format_indicator,
            message_expiry_interval,
            content_type,
            response_topic,
            correlation_data,
            user_properties,
        }))
    }

    pub fn write(properties: &LastWillProperties, buffer: &mut BytesMut) -> Result<(), Error> {
        let len = len(properties);
        write_remaining_length(buffer, len)?;

        if let Some(delay_interval) = properties.delay_interval {
            buffer.put_u8(PropertyType::WillDelayInterval as u8);
            buffer.put_u32(delay_interval);
        }

        if let Some(payload_format_indicator) = properties.payload_format_indicator {
            buffer.put_u8(PropertyType::PayloadFormatIndicator as u8);
            buffer.put_u8(payload_format_indicator);
        }

        if let Some(message_expiry_interval) = properties.message_expiry_interval {
            buffer.put_u8(PropertyType::MessageExpiryInterval as u8);
            buffer.put_u32(message_expiry_interval);
        }

        if let Some(content_type_value) = &properties.content_type {
            buffer.put_u8(PropertyType::ContentType as u8);
            write_mqtt_string(buffer, content_type_value);
        }

        if let Some(topic) = &properties.response_topic {
            buffer.put_u8(PropertyType::ResponseTopic as u8);
            write_mqtt_string(buffer, topic);
        }

        if let Some(data) = &properties.correlation_data {
            buffer.put_u8(PropertyType::CorrelationData as u8);
            write_mqtt_bytes(buffer, data);
        }

        for (key, value) in properties.user_properties.iter() {
            buffer.put_u8(PropertyType::UserProperty as u8);
            write_mqtt_string(buffer, key);
            write_mqtt_string(buffer, value);
        }

        Ok(())
    }
}

pub mod login {
    use super::*;

    pub fn new<U: Into<String>, P: Into<String>>(u: U, p: P) -> Login {
        Login {
            username: u.into(),
            password: p.into(),
        }
    }

    pub fn read(connect_flags: u8, bytes: &mut Bytes) -> Result<Option<Login>, Error> {
        let username = match connect_flags & 0b1000_0000 {
            0 => String::new(),
            _ => read_mqtt_string(bytes)?,
        };

        let password = match connect_flags & 0b0100_0000 {
            0 => String::new(),
            _ => read_mqtt_string(bytes)?,
        };

        if username.is_empty() && password.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Login { username, password }))
        }
    }

    pub fn len(login: &Login) -> usize {
        let mut len = 0;

        if !login.username.is_empty() {
            len += 2 + login.username.len();
        }

        if !login.password.is_empty() {
            len += 2 + login.password.len();
        }

        len
    }

    pub fn write(login: &Login, buffer: &mut BytesMut) -> u8 {
        let mut connect_flags = 0;
        if !login.username.is_empty() {
            connect_flags |= 0x80;
            write_mqtt_string(buffer, &login.username);
        }

        if !login.password.is_empty() {
            connect_flags |= 0x40;
            write_mqtt_string(buffer, &login.password);
        }

        connect_flags
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_connect_v5() {
        use super::*;

        let client_id = String::from("test_client_id");
        let mut buffer = BytesMut::new();
        let connect: Connect = Connect {
            keep_alive: 30u16, // 30 seconds
            client_id,
            clean_session: true,
        };

        let login: Login = Login {
            username: String::from("test_user"),
            password: String::from("test_password"),
        };

        let will_topic = Bytes::from("will_topic");
        let will_message = Bytes::from("will_message");
        let lastwill: LastWill = LastWill {
            topic: will_topic,
            message: will_message,
            qos: QoS::AtLeastOnce,
            retain: true,
        };

        let user_properties: Vec<(String, String)> = vec![
            ("username".into(), "justin".into()),
            ("tag".to_string(), "middleware".to_string()),
        ];
        let authentication_method: String = "SCRAM-SHA-256".to_string();
        let authentication_data: Bytes = Bytes::from("client-first-data");
        let properties: ConnectProperties = ConnectProperties {
            session_expiry_interval: Some(30u32), // 30 seconds as expiry interval
            receive_maximum: Some(1024u16),
            max_packet_size: Some(2048u32),
            topic_alias_max: Some(100u16),
            request_response_info: Some(1u8), // require response message or not (1 or 0) from connack
            request_problem_info: Some(1u8),  // require response message or not (1 or 0)
            user_properties,
            authentication_method: Some(authentication_method),
            authentication_data: Some(authentication_data),
        };

        let will_user_properties: Vec<(String, String)> = vec![
            ("will_user".into(), "peter".into()),
            ("tag".to_string(), "middleware".to_string()),
        ];
        let will_properties: LastWillProperties = LastWillProperties {
            delay_interval: Some(60u32),
            payload_format_indicator: Some(1u8), // 1 or 0 to demonstrate the payload format is UTF-8 or not
            message_expiry_interval: Some(60u32),
            content_type: Some("content-type".to_string()),
            response_topic: Some("response-topic".to_string()),
            correlation_data: Some(Bytes::from("correlation-data")),
            user_properties: will_user_properties,
        };

        // test the write method of connect packet in v5
        write(
            &connect,
            &Some(properties),
            &Some(lastwill),
            &Some(will_properties),
            &Some(login),
            &mut buffer,
        )
        .unwrap();

        // read the fixed header
        let fixedheader: FixedHeader = parse_fixed_header(buffer.iter()).unwrap();
        // test the display of fixheader
        println!("fixheader: {fixedheader}");
        // read first byte and check its packet type which should be connect
        assert_eq!(fixedheader.byte1, 0b0001_0000);
        assert_eq!(fixedheader.fixed_header_len, 3);
        assert!(fixedheader.remaining_len == 273);
        // test the read method of connect packet in v5 and verify the result of the write method
        let ConnectReadOutcome {
            protocol_version: _,
            connect,
            properties: connectproperties,
            last_will,
            last_will_properties,
            login,
        } = read(fixedheader, buffer.copy_to_bytes(buffer.len())).unwrap();

        assert_eq!(connect.client_id, "test_client_id");
        assert_eq!(connect.keep_alive, 30u16);
        assert!(connect.clean_session);

        let connect_properties = connectproperties.unwrap();
        assert_eq!(connect_properties.session_expiry_interval, Some(30u32));
        assert_eq!(connect_properties.receive_maximum, Some(1024u16));
        assert_eq!(connect_properties.max_packet_size, Some(2048u32));
        assert_eq!(connect_properties.topic_alias_max, Some(100u16));
        assert_eq!(connect_properties.request_response_info, Some(1u8));
        assert_eq!(connect_properties.request_problem_info, Some(1u8));
        assert_eq!(
            connect_properties.user_properties.first().unwrap(),
            &("username".to_string(), "justin".to_string())
        );
        assert_eq!(
            connect_properties.authentication_method,
            Some("SCRAM-SHA-256".to_string())
        );
        assert_eq!(
            connect_properties.authentication_data,
            Some(Bytes::from("client-first-data"))
        );

        let login_read = login.unwrap();
        assert_eq!(login_read.username, "test_user");
        assert_eq!(login_read.password, "test_password");

        let lastwill_read = last_will.unwrap();
        assert_eq!(lastwill_read.topic, "will_topic");
        assert_eq!(lastwill_read.message, "will_message");
        assert_eq!(lastwill_read.qos, QoS::AtLeastOnce);
        assert!(lastwill_read.retain);

        let lastwillproperties_read = last_will_properties.unwrap();
        assert_eq!(lastwillproperties_read.delay_interval, Some(60u32));
        assert_eq!(lastwillproperties_read.payload_format_indicator, Some(1u8));
        assert_eq!(lastwillproperties_read.message_expiry_interval, Some(60u32));
        assert_eq!(
            lastwillproperties_read.content_type,
            Some("content-type".to_string())
        );
        assert_eq!(
            lastwillproperties_read.response_topic,
            Some("response-topic".to_string())
        );
        assert_eq!(
            lastwillproperties_read.correlation_data,
            Some(Bytes::from("correlation-data"))
        );
        assert_eq!(
            lastwillproperties_read.user_properties.first().unwrap(),
            &("will_user".to_string(), "peter".to_string())
        );

        println!("connect in v5 display starts...........................");
        print!("{connect_properties}");
        print!("{login_read}");
        print!("{connect}");
        print!("{lastwill_read}");
        println!("{lastwillproperties_read}");
        println!("connect in v5 display ends.............................");
    }
}
