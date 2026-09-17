#!/bin/bash
mkdir -p crops ocr_crops
img=road_1.png
w=$(identify -format "%w" $img)
h=$(identify -format "%h" $img)
echo "Image size: ${w}x${h}"
# define crop boxes: use percentages
declare -a boxes=("0,0,$((w/3)),$((h/4))" "$((w/3)),0,$((w/3)),$((h/4))" "$((2*w/3)),0,$((w/3)),$((h/4))" 
"0,$((h/4)),$((w/3)),$((h/4))" "$((w/3)),$((h/4)),$((w/3)),$((h/4))" "$((2*w/3)),$((h/4)),$((w/3)),$((h/4))" 
"0,$((h/2)),$((w/3)),$((h/4))" "$((w/3)),$((h/2)),$((w/3)),$((h/4))" "$((2*w/3)),$((h/2)),$((w/3)),$((h/4))")

i=0
for b in "${boxes[@]}"; do
  IFS=',' read x y ww hh <<< "$b"
  out=crops/crop_${i}.png
  convert "$img" -crop ${ww}x${hh}+${x}+${y} +repage "$out"
  # enhance
  convert "$out" -colorspace Gray -normalize -sharpen 0x1 -contrast-stretch 0.5% ocr_crops/crop_${i}_enh.png
  tesseract ocr_crops/crop_${i}_enh.png ocr_crops/crop_${i}_psm6 -l eng --psm 6 >/dev/null 2>&1 || true
  if [ -f ocr_crops/crop_${i}_psm6.txt ]; then echo "---- crop_${i} ----"; sed -n '1,120p' ocr_crops/crop_${i}_psm6.txt; fi
  i=$((i+1))
done

# Also try detecting green sign areas: extract green channel and threshold
convert "$img" -colorspace RGB -channel G -separate +channel g_channel.png
convert g_channel.png -normalize -threshold 60% g_thresh.png
# find bounding boxes of connected components via convert -connected-components
convert g_thresh.png -define connected-components:verbose=true -connected-components 8 cc.png > cc.txt || true
echo "connected components:"; sed -n '1,200p' cc.txt
