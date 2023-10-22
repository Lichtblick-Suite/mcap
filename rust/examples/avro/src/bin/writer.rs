use apache_avro::Schema;
use serde::Serialize;
use std::borrow::Cow;
use std::fs::File;
use std::io::BufWriter;
use std::sync::Arc;

#[derive(Debug, Serialize)]
struct Time {
    sec: i64,
    nsec: i64,
}

#[derive(Debug, Serialize)]
struct Vector3 {
    x: f64,
    y: f64,
    z: f64,
}

#[derive(Debug, Serialize)]
struct Quaternion {
    x: f64,
    y: f64,
    z: f64,
    w: f64,
}

#[derive(Debug, Serialize)]

struct Pose {
    position: Vector3,
    orientation: Quaternion,
}

#[derive(Debug, Serialize)]

struct PosesInFrame {
    timestamp: Time,
    frame_id: String,
    poses: Vec<Pose>,
}

fn main() {
    let raw_schema_time = r#"
    {
        "type": "record",
        "namespace": "foxglove",
        "name": "Time",
        "fields": [
            { "name": "sec", "type": "long" },
            { "name": "nsec", "type": "long" }
        ]
    }"#;

    let raw_schema_vector = r#"
    {
        "type": "record",
        "namespace": "foxglove",
        "name": "Vector3",
        "fields": [
            { "name": "x", "type": "double" },
            { "name": "y", "type": "double" },
            { "name": "z", "type": "double" }
        ]
    }"#;

    let raw_schema_quaternion = r#"
    {
        "type": "record",
        "namespace": "foxglove",
        "name": "Quaternion",
        "fields": [
            { "name": "x", "type": "double" },
            { "name": "y", "type": "double" },
            { "name": "z", "type": "double" },
            { "name": "w", "type": "double" }
        ]
    }"#;

    let raw_schema_pose = r#"
    {
        "type": "record",
        "namespace": "foxglove",
        "name": "Pose",
        "fields": [
            { "name": "position", "type": "Vector3" },
            { "name": "orientation", "type": "Quaternion" }
        ]
    }"#;

    let raw_schema_poses_in_frame = r#"
    {
        "type": "record",
        "namespace": "foxglove",
        "name": "PosesInFrame",
        "fields": [
            { "name": "timestamp", "type": "Time" },
            { "name": "frame_id", "type": "string" },
            { "name": "poses", "type": { "type": "array", "items": "Pose" } }
        ]
    }"#;

    let schemas = Schema::parse_list(&[
        raw_schema_time,
        raw_schema_vector,
        raw_schema_quaternion,
        raw_schema_pose,
        raw_schema_poses_in_frame,
    ])
    .unwrap();

    // for multiple schemas we need to write them as an array
    let arr = format!(
        "[{}]",
        vec![
            raw_schema_time,
            raw_schema_vector,
            raw_schema_quaternion,
            raw_schema_pose,
            raw_schema_poses_in_frame
        ]
        .join(",")
    );

    let schema_b = mcap::Schema {
        name: "foxglove.PosesInFrame".to_string(),
        encoding: "avro".to_string(),
        data: Cow::Borrowed(arr.as_bytes()),
    };

    let channel_poses = mcap::Channel {
        schema: Some(Arc::new(schema_b.to_owned())),
        topic: "poses".to_string(),
        message_encoding: "avro".to_string(),
        metadata: std::collections::BTreeMap::new(),
    };

    let mut avro_mcap =
        mcap::Writer::new(BufWriter::new(File::create("avro.mcap").unwrap())).unwrap();

    avro_mcap
        .add_channel(&channel_poses)
        .expect("Couldn't write channel");

    {
        // fetch_schema_ref? but not accessible cause we don't get the parser that parse_list uses
        let time_schema = schemas.get(0).unwrap();
        let vector3_schema = schemas.get(1).unwrap();
        let quat_schema = schemas.get(2).unwrap();
        let pose_schema = schemas.get(3).unwrap();
        let poses_schema = schemas.get(4).unwrap();

        let pose_1 = Pose {
            position: Vector3 {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            },
            orientation: Quaternion {
                x: 0.0,
                y: 0.0,
                z: 0.0,
                w: 0.0,
            },
        };

        let pose_2 = Pose {
            position: Vector3 {
                x: 1.0,
                y: 1.0,
                z: 1.0,
            },
            orientation: Quaternion {
                x: 0.0,
                y: 0.0,
                z: 0.0,
                w: 0.0,
            },
        };

        let poses = PosesInFrame {
            timestamp: Time {
                sec: 0i64,
                nsec: 0i64,
            },
            frame_id: "frame".to_string(),
            poses: vec![pose_1, pose_2],
        };

        {
            let encoded = apache_avro::to_avro_datum_schemata(
                &poses_schema,
                [time_schema, vector3_schema, quat_schema, pose_schema].into(),
                apache_avro::to_value(&poses).unwrap(),
            )
            .unwrap();

            let message = mcap::Message {
                channel: Arc::new(channel_poses.to_owned()),
                data: Cow::from(encoded),
                log_time: 1000000,
                publish_time: 0,
                sequence: 0,
            };

            avro_mcap.write(&message).unwrap();
        }
    }

    avro_mcap.finish().unwrap();
}
