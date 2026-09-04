import { io } from 'socket.io-client'

const PUBLIC_API =
  import.meta.env.VITE_API_URL ||
  'https://antenna-dangerous-between-finite.trycloudflare.com'

export const API = ''
export const socket = io(API, {
  autoConnect: true,
  withCredentials: true,
})
