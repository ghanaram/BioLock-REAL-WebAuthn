import { io } from "socket.io-client";

export const API =
  import.meta.env.VITE_API_URL ||
  "https://suit-entity-granny-finally.trycloudflare.com";

export const socket = io(API, {
  autoConnect: true,
});