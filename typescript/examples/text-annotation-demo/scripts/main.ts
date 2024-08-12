import {
  CameraCalibration as CameraCalibrationSchema,
  RawImage as RawImageSchema,
  ImageAnnotations as ImageAnnotationsSchema,
} from "@foxglove/schemas/jsonschema";
import { Time } from "@foxglove/schemas/schemas/typescript/Time";
import { McapWriter } from "@mcap/core";
import { FileHandleWritable } from "@mcap/nodejs";
import { open } from "fs/promises";

import Scene from "./Scene";

const framesPerSecond = 30;
const lengthSeconds = 10; // seconds

async function main() {
  const mcapFilePath = "text-annotation-example.mcap";
  const fileHandle = await open(mcapFilePath, "w");
  const fileHandleWritable = new FileHandleWritable(fileHandle);

  const mcapFile = new McapWriter({
    writable: fileHandleWritable,
    useStatistics: true,
    useChunks: true,
    useChunkIndex: true,
  });

  await mcapFile.start({
    profile: "",
    library: "mcap example",
  });

  const calibrationSchemaId = await mcapFile.registerSchema({
    name: CameraCalibrationSchema.title,
    encoding: "jsonschema",
    data: Buffer.from(JSON.stringify(CameraCalibrationSchema)),
  });

  const calibrationChannelId = await mcapFile.registerChannel({
    schemaId: calibrationSchemaId,
    topic: "calibration",
    messageEncoding: "json",
    metadata: new Map(),
  });

  const imageSchemaId = await mcapFile.registerSchema({
    name: RawImageSchema.title,
    encoding: "jsonschema",
    data: Buffer.from(JSON.stringify(RawImageSchema)),
  });

  const imageChannelId = await mcapFile.registerChannel({
    schemaId: imageSchemaId,
    topic: "camera",
    messageEncoding: "json",
    metadata: new Map(),
  });

  const annotationSchemaId = await mcapFile.registerSchema({
    name: ImageAnnotationsSchema.title,
    encoding: "jsonschema",
    data: Buffer.from(JSON.stringify(ImageAnnotationsSchema)),
  });

  const annotationsChannelId = await mcapFile.registerChannel({
    schemaId: annotationSchemaId,
    topic: "annotations",
    messageEncoding: "json",
    metadata: new Map(),
  });

  const scene = new Scene({
    width: 800,
    height: 600,
    frameId: "cam",
    ballRadius: 5,
    gravityCoefficient: 0.005,
  });

  const deltaBetweenFrames = 1 / framesPerSecond;

  for (
    let currentTimeSeconds = 0;
    currentTimeSeconds < lengthSeconds;
    currentTimeSeconds += deltaBetweenFrames
  ) {
    scene.renderScene();

    const bigTime = Math.floor(currentTimeSeconds * 1_000_000_000);
    const rosTime = fromNanoSec(bigTime);

    await mcapFile.addMessage({
      channelId: calibrationChannelId,
      sequence: 0,
      publishTime: 0,
      logTime: bigTime,
      data: Buffer.from(JSON.stringify(scene.getCameraCalibration(rosTime))),
    });
    await mcapFile.addMessage({
      channelId: imageChannelId,
      sequence: 0,
      publishTime: 0,
      logTime: bigTime,
      data: Buffer.from(JSON.stringify(scene.getRawImage(rosTime))),
    });
    await mcapFile.addMessage({
      channelId: annotationsChannelId,
      sequence: 0,
      publishTime: 0,
      logTime: bigTime,
      data: Buffer.from(JSON.stringify(scene.getImageAnnotations(rosTime))),
    });
  }

  await mcapFile.end();
}

/**
 * Convert an integer number of nanoseconds to Time
 * @param nsec Nanoseconds integer
 * @returns Time object
 */
function fromNanoSec(nsec: number): Time {
  // From https://github.com/ros/roscpp_core/blob/86720717c0e1200234cc0a3545a255b60fb541ec/rostime/include/ros/impl/time.h#L63
  // and https://github.com/ros/roscpp_core/blob/7583b7d38c6e1c2e8623f6d98559c483f7a64c83/rostime/src/time.cpp#L536
  //
  // Note: 1e9 is slower than writing out the number
  return { sec: Number(nsec / 1_000_000_000), nsec: Number(nsec % 1_000_000_000) };
}

void main();
