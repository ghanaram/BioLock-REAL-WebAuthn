import { io } from "socket.io-client";

export const API =
  import.meta.env.VITE_API_URL ||
  "https://antenna-dangerous-between-finite.trycloudflare.com";

export const socket = io(API, {
  autoConnect: true,
});