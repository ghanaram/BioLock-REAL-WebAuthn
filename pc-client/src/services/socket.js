import { io } from 'socket.io-client'
export const API = import.meta.env.VITE_API_URL || 'https://soma-beam-fragrance-wanting.trycloudflare.com'
export const socket = io(API,{autoConnect:true})
