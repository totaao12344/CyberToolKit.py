from PIL import Image, ImageDraw

# Crear una nueva imagen con tamaño 800x600 píxeles y fondo azul claro
img = Image.new('RGB', (800, 600), color=(135, 206, 250))

# Crear un objeto de dibujo
d = ImageDraw.Draw(img)

# Dibujar un texto en negro
d.text((300, 280), "CyberToolKit Background", fill=(0, 0, 0))

# Guardar la imagen
img.save('background.jpg')

print("Imagen de fondo generada y guardada como 'background.jpg'")



