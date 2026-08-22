import { io } from 'socket.io-client'
export const API = import.meta.env.VITE_API_URL || 'https://192.168.0.141:5000'
export const socket = io(API,{autoConnect:true})
