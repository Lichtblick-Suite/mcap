export type McapMagic = {
  specVersion: "0";
};
export type Header = {
  profile: string;
  library: string;
};
export type Footer = {
  summaryStart: number;
  summaryOffsetStart: number;
  summaryCrc: number;
};
export type Schema = {
  id: number;
  name: string;
  encoding: string;
  data: Uint8Array;
};
export type Channel = {
  id: number;
  schemaId: number;
  topic: string;
  messageEncoding: string;
  metadata: Map<string, string>;
};
export type Message = {
  channelId: number;
  sequence: number;
  logTime: number;
  publishTime: number;
  data: Uint8Array;
};
export type Chunk = {
  messageStartTime: number;
  messageEndTime: number;
  uncompressedSize: number;
  uncompressedCrc: number;
  compression: string;
  records: Uint8Array;
};
export type MessageIndex = {
  channelId: number;
  records: [logTime: number, offset: number][];
};
export type ChunkIndex = {
  messageStartTime: number;
  messageEndTime: number;
  chunkStartOffset: number;
  chunkLength: number;
  messageIndexOffsets: Map<number, number>;
  messageIndexLength: number;
  compression: string;
  compressedSize: number;
  uncompressedSize: number;
};
export type Attachment = {
  name: string;
  logTime: number;
  createTime: number;
  mediaType: string;
  data: Uint8Array;
};
export type AttachmentIndex = {
  offset: number;
  length: number;
  logTime: number;
  createTime: number;
  dataSize: number;
  name: string;
  mediaType: string;
};
export type Statistics = {
  messageCount: number;
  schemaCount: number;
  channelCount: number;
  attachmentCount: number;
  metadataCount: number;
  chunkCount: number;
  messageStartTime: number;
  messageEndTime: number;
  channelMessageCounts: Map<number, number>;
};
export type Metadata = {
  name: string;
  metadata: Map<string, string>;
};
export type MetadataIndex = {
  offset: number;
  length: number;
  name: string;
};
export type SummaryOffset = {
  groupOpcode: number;
  groupStart: number;
  groupLength: number;
};
export type DataEnd = {
  dataSectionCrc: number;
};
export type UnknownRecord = {
  opcode: number;
  data: Uint8Array;
};

export type McapRecords = {
  Header: Header;
  Footer: Footer;
  Schema: Schema;
  Channel: Channel;
  Message: Message;
  Chunk: Chunk;
  MessageIndex: MessageIndex;
  ChunkIndex: ChunkIndex;
  Attachment: Attachment;
  AttachmentIndex: AttachmentIndex;
  Statistics: Statistics;
  Metadata: Metadata;
  MetadataIndex: MetadataIndex;
  SummaryOffset: SummaryOffset;
  DataEnd: DataEnd;
  Unknown: UnknownRecord;
};

export type TypedMcapRecords = {
  [R in keyof McapRecords]: McapRecords[R] & { type: R };
};

type Values<T> = T[keyof T];
export type TypedMcapRecord = Values<TypedMcapRecords>;
export type McapRecord = Values<McapRecords>;

export type DecompressHandlers = {
  [compression: string]: (buffer: Uint8Array, decompressedSize: number) => Uint8Array;
};

/**
 * IReadable describes a random-access reader interface.
 */
export interface IReadable {
  size(): Promise<number>;
  read(offset: number, size: number): Promise<Uint8Array>;
}
